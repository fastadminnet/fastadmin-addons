<?php

namespace think\addons;

use PhpZip\ZipFile;
use think\Db;
use think\Exception;

/**
 * 插件安装安全校验组件
 *
 * 用于加固在线安装/升级链路：
 *   1. 传输层：强制 TLS 证书校验（系统 CA 或自定义 CA）与可选 SPKI 证书固定，限制自动重定向；
 *   2. 包完整性：解压与实例化前强制校验包结构、名称、zip-slip，并基于本地公钥验签
 *      或官方 API 的 /addon/valid 做 md5 验证；
 *   3. 落地执行：install.sql 受控迁移白名单，禁止 public/ 目录可执行脚本复制到站点根。
 *
 * 签名支持两种形态：
 *   - 清单签名（推荐）：对 addon-manifest-v1 清单文本签名，清单内绑定 name/version/sha256/有效期/keyid，
 *     可防旧包重放与降级；公钥按 keyid 从公钥环（addon_sign_keys）中选择，支持轮换与吊销；
 *   - 裸签名（不携带 keyid）：对 zip 原始字节直接签名，由公钥环中任一未吊销公钥校验，
 *     不具备有效期与版本约束，仅用于过渡期，建议统一使用清单签名。
 *
 * 本地安装（上传 zip）与远程安装使用同一套清单验签：
 *   - 正常路径：Service::local() 调用官方 API 验证（POST /addon/valid），服务端在 data 段回传信封后登记；
 *   - 兜底路径：服务端未回传签名时使用 addon_sign_local_pins 中官网签发的信封；
 *   - 两者都不满足时直接拒绝，不存在「跳过验签」的放行开关。
 */
class Security
{
    /** 清单格式标识，必须是清单文本的第一行 */
    const MANIFEST_MAGIC = 'addon-manifest-v1';

    /** @var array 已校验通过的包缓存，避免同一请求内重复远端校验 */
    private static $verified = [];

    /** @var array 本次请求内下载并校验的包签名（真实路径 => 签名），供 install()/upgrade() 二次校验复用 */
    private static $signatures = [];

    /** @var array 最近一次跟随重定向时，重定向响应（3xx）上的签名响应头 */
    private static $hopHeaders = [];

    /**
     * 登记刚下载并校验的包签名，仅供同一请求内 install()/upgrade() 的二次校验使用。
     *
     * 签名只在内存中传递，不落盘。
     *
     * @param string $file      插件包路径
     * @param string $signature 下载响应中的签名（裸 base64 或 JSON 信封）
     * @return void
     */
    public static function registerSignature($file, $signature)
    {
        $signature = trim((string)$signature);
        if ($signature === '') {
            return;
        }
        self::$signatures[realpath($file) ?: $file] = $signature;
    }

    /**
     * 应用传输层安全选项：系统 CA（或自定义 CA）、可选 SPKI 证书固定、受限重定向。
     *
     * @param array $options Guzzle 客户端选项
     * @return array
     * @throws Exception
     */
    public static function applyTransportOptions(array $options)
    {
        // CA 校验：默认使用系统 CA Bundle；配置 addon_api_ca_bundle 时使用指定证书
        $caBundle = trim((string)config('fastadmin.addon_api_ca_bundle'));
        if ($caBundle !== '') {
            if (!is_file($caBundle)) {
                throw new Exception('Configured addon API CA bundle does not exist');
            }
            $options['verify'] = $caBundle;
        } else {
            $options['verify'] = true;
        }

        // 证书固定：配置 sha256 SPKI 指纹（sha256// 前缀可省略，多个用数组）
        $pins = [];
        foreach ((array)config('fastadmin.addon_api_pins') as $pin) {
            $pin = trim((string)$pin);
            if ($pin === '') {
                continue;
            }
            $pins[] = strpos($pin, 'sha256//') === 0 ? $pin : 'sha256//' . $pin;
        }
        if ($pins) {
            if (!defined('CURLOPT_PINNEDPUBLICKEY')) {
                throw new Exception('Certificate pinning requires a libcurl build with CURLOPT_PINNEDPUBLICKEY');
            }
            if (!isset($options['curl']) || !is_array($options['curl'])) {
                $options['curl'] = [];
            }
            $options['curl'][CURLOPT_PINNEDPUBLICKEY] = implode(';', $pins);
        }

        // 限制自动重定向：每一跳都校验目标（仅 https + 受信主机），并记录该跳的签名响应头。
        // 签名可能挂在 302 响应上（服务端校验授权后重定向到 CDN），而 Guzzle 只返回最终
        // 响应，中间跳的响应头会丢失，因此由 on_redirect 统一收集。
        $options['allow_redirects'] = [
            'max'         => 3,
            'strict'      => true,
            'referer'     => false,
            'on_redirect' => function ($request, $response, $uri) {
                // assertTrustedUrl 同时强制 https，可阻断 302 到 http 的降级
                self::assertTrustedUrl((string)$uri);
                self::rememberHopHeaders($response);
            },
        ];

        return $options;
    }

    /**
     * 清空上一轮重定向收集到的签名响应头。
     *
     * @return void
     */
    public static function resetHopHeaders()
    {
        self::$hopHeaders = [];
    }

    /**
     * 记录重定向响应上的签名头（X-Addon-Signature / Keyid / Manifest）。
     *
     * @param mixed $response PSR-7 响应
     * @return void
     */
    public static function rememberHopHeaders($response)
    {
        foreach (['signature' => 'X-Addon-Signature', 'keyid' => 'X-Addon-Keyid', 'manifest' => 'X-Addon-Manifest'] as $key => $header) {
            $value = trim((string)$response->getHeaderLine($header));
            if ($value !== '') {
                self::$hopHeaders[$key] = $value;
            }
        }
    }

    /**
     * 取重定向过程中收集到的签名头。
     *
     * @return array signature/keyid/manifest
     */
    public static function hopHeaders()
    {
        return self::$hopHeaders;
    }

    /**
     * 校验下载 URL 是否位于受信域名（官方 API 域或其主域子域，或配置的额外域名）。
     *
     * @param string $url
     * @return bool
     * @throws Exception
     */
    public static function assertTrustedUrl($url)
    {
        $host = strtolower((string)parse_url((string)$url, PHP_URL_HOST));
        $scheme = strtolower((string)parse_url((string)$url, PHP_URL_SCHEME));
        if ($scheme !== 'https' || $host === '') {
            throw new Exception('Untrusted addon download URL');
        }

        foreach (self::trustedHosts() as $item) {
            if ($host === $item || substr($host, -strlen('.' . $item)) === '.' . $item) {
                return true;
            }
        }
        throw new Exception('Untrusted addon download URL');
    }

    /**
     * 受信下载主机列表。
     *
     * @return array
     */
    private static function trustedHosts()
    {
        $hosts = [];
        $apiHost = strtolower((string)parse_url((string)config('fastadmin.api_url'), PHP_URL_HOST));
        if ($apiHost !== '') {
            $hosts[] = $apiHost;
            // 同时信任主域及其子域（官方 CDN 通常为 api 主域的同级子域，如 cdn.fastadmin.net）
            $labels = explode('.', $apiHost);
            if (count($labels) > 2) {
                $hosts[] = implode('.', array_slice($labels, 1));
            }
        }
        foreach ((array)config('fastadmin.addon_download_hosts') as $host) {
            $host = strtolower(trim((string)$host));
            if ($host !== '') {
                $hosts[] = $host;
            }
        }
        return array_values(array_unique($hosts));
    }

    /**
     * 公钥环：keyid => 公钥 PEM 内容或 PEM 文件路径。
     *
     * 来源仅为 addon_sign_keys，每个 keyid 对应一把公钥，轮换期可并存多把。
     *
     * @return array
     */
    public static function keyRing()
    {
        $keys = [];
        foreach ((array)config('fastadmin.addon_sign_keys') as $id => $value) {
            $id = trim((string)$id);
            $value = trim((string)$value);
            if ($id === '' || $value === '') {
                continue;
            }
            $keys[$id] = $value;
        }
        return $keys;
    }

    /**
     * 本地安装签名包：插件名 => 向官方 API 申请并下载到的签名信封，支持：
     *   'demo' => '<信封 JSON>'                                        // scripts/addon-sign.php 的输出
     *   'demo' => ['signature' => '...', 'keyid' => '...', 'manifest' => '...']
     *   'demo' => [ <上述任意形式>, ... ]                               // 同一插件的多个版本
     *
     * 仅作为「在线申请签名不可用」时的离线兜底，验签链与远程安装完全一致：
     * 必须包含 keyid、清单与签名，由 verifyManifest() 统一校验。
     * 清单字段与接口传输一致，必须是 base64_encode 后的值（官网下发即为此形式）。
     * 不接受裸签名——裸签名没有清单，无法约束名称、版本、sha256、有效期与防降级。
     *
     * @param string $name 插件标识
     * @return array 规范化后的信封字符串列表
     */
    private static function localPinSignatures($name)
    {
        $pins = (array)config('fastadmin.addon_sign_local_pins');
        $entry = $pins[$name] ?? null;
        if ($entry === null || $entry === '') {
            return [];
        }
        // 单个信封或单个结构化条目，统一包成列表
        if (is_string($entry) || self::isEnvelopeSource($entry)) {
            $entry = [$entry];
        }

        $signatures = [];
        foreach ((array)$entry as $item) {
            if (self::isEnvelopeSource($item)) {
                $item = self::buildEnvelopeEncoded(
                    (string)($item['signature'] ?? ''),
                    (string)($item['keyid'] ?? ''),
                    (string)($item['manifest'] ?? '')
                );
            }
            $item = trim((string)$item);
            // 只接受完整信封，裸签名无法参与清单校验
            if ($item === '' || self::parseEnvelope($item) === null) {
                continue;
            }
            $signatures[] = $item;
        }
        return array_values(array_unique($signatures));
    }

    /**
     * 判断配置项是否为结构化的签名信封（signature + keyid + manifest）。
     *
     * @param mixed $value
     * @return bool
     */
    private static function isEnvelopeSource($value)
    {
        return is_array($value) && isset($value['signature']);
    }

    /**
     * 用配置中的官方签发信封完成本地安装验签（逐候选尝试，任一通过即成功）。
     *
     * 与远程安装共用 verifyManifest()，因此 keyid 信任、吊销、清单签名、
     * 名称/版本/sha256、有效期与防降级全部生效。
     *
     * @param string $file   插件包路径
     * @param string $name   插件标识
     * @param array  $config 包内 info.ini 解析结果
     * @return bool
     * @throws Exception
     */
    private static function verifyWithLocalPins($file, $name, array $config)
    {
        $signatures = self::localPinSignatures($name);
        if (!$signatures) {
            throw new Exception('Addon package signature missing');
        }

        $lastError = '';
        foreach ($signatures as $signature) {
            $envelope = self::parseEnvelope($signature);
            if ($envelope === null) {
                continue;
            }
            try {
                return self::verifyManifest($file, $name, $envelope, $config);
            } catch (\Throwable $e) {
                $lastError = __($e->getMessage());
            }
        }
        throw new Exception(__('Addon local signature rejected: %s', $lastError ?: __('No usable signature')));
    }

    /**
     * 已吊销的 keyid 列表（私钥泄露时只需下发一个 keyid，站点侧立即拒绝该密钥签发的所有包）。
     *
     * @return array
     */
    public static function revokedKeyIds()
    {
        $list = [];
        foreach ((array)config('fastadmin.addon_sign_revoked_keyids') as $id) {
            $id = trim((string)$id);
            if ($id !== '') {
                $list[] = $id;
            }
        }
        return $list;
    }

    /**
     * 公钥值归一化为 PEM 文本（支持直接写 PEM 或写文件路径）。
     *
     * @param string $value
     * @return string
     */
    private static function loadPublicKey($value)
    {
        $value = trim((string)$value);
        if ($value === '') {
            return '';
        }
        if (strpos($value, 'BEGIN') !== false) {
            return $value;
        }
        if (is_file($value)) {
            $pem = @file_get_contents($value);
            if ($pem !== false && trim($pem) !== '') {
                return $pem;
            }
        }
        return '';
    }

    /**
     * 把「签名 + keyid + 清单原文」组装成传输用信封（JSON 字符串）。
     * 未提供 keyid/manifest 时原样返回，交由裸签名分支校验。
     *
     * 清单在信封内一律 base64（服务端输出同样一律 base64），客户端只解码一次。
     *
     * @param string $signature base64 签名
     * @param string $keyid     签发密钥标识
     * @param string $manifest  清单原文（未 base64）
     * @return string
     */
    public static function buildEnvelope($signature, $keyid = '', $manifest = '')
    {
        $manifest = (string)$manifest;
        return self::buildEnvelopeEncoded($signature, $keyid, $manifest === '' ? '' : base64_encode($manifest));
    }

    /**
     * 用「已 base64 编码的清单」组装信封，不做二次编码。
     *
     * 服务端约定：X-Addon-Manifest Header 与 data.manifest 始终输出
     * base64_encode(清单原文)，客户端收到后原样放入信封，验签时只解码一次。
     *
     * @param string $signature       base64 签名
     * @param string $keyid           签发密钥标识
     * @param string $manifestEncoded base64 编码后的清单
     * @return string
     */
    public static function buildEnvelopeEncoded($signature, $keyid = '', $manifestEncoded = '')
    {
        $signature = trim((string)$signature);
        $keyid = trim((string)$keyid);
        $manifestEncoded = trim((string)$manifestEncoded);
        if ($signature === '' || $keyid === '' || $manifestEncoded === '') {
            return $signature;
        }
        return (string)json_encode([
            'v'        => 1,
            'keyid'    => $keyid,
            'manifest' => $manifestEncoded,
            'sig'      => $signature,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * 解析信封；非信封（裸签名）返回 null。
     *
     * @param string $signature
     * @return array|null
     */
    public static function parseEnvelope($signature)
    {
        $signature = trim((string)$signature);
        if ($signature === '' || substr($signature, 0, 1) !== '{') {
            return null;
        }
        $json = json_decode($signature, true);
        if (!is_array($json) || empty($json['sig']) || empty($json['manifest'])) {
            return null;
        }
        return $json;
    }

    /**
     * 解码信封内 base64 编码的清单原文。
     *
     * 约定：清单（多行文本）在信封、Header、接口 JSON 中一律以 base64 传输，
     * 因此这里只做一次 base64 解码，不再兼容其它形态；解不出清单直接判定格式非法，
     * 避免服务端少编一次码就静默降级成「按原文验签」。
     *
     * @param string $value
     * @return string
     * @throws Exception
     */
    private static function decodeManifest($value)
    {
        $value = trim((string)$value);
        if ($value === '') {
            throw new Exception('Addon manifest format invalid');
        }
        $decoded = base64_decode($value, true);
        if ($decoded === false || strpos($decoded, self::MANIFEST_MAGIC) !== 0) {
            throw new Exception('Addon manifest format invalid');
        }
        return $decoded;
    }

    /**
     * 把清单编码为 HTTP Header / JSON 字段的值（服务端使用，始终 base64）。
     *
     * Header 不允许出现裸换行，直接输出清单会被 PHP/网关拒绝
     * （"Header may not contain more than a single header, new line detected"），
     * 因此服务端输出 X-Addon-Manifest 或 data.manifest 时必须经过本方法。
     *
     * @param string $manifest 清单原文
     * @return string
     */
    public static function manifestHeaderValue($manifest)
    {
        $manifest = (string)$manifest;
        return $manifest === '' ? '' : base64_encode($manifest);
    }

    /**
     * 解析清单文本为 key => value（首行必须为 addon-manifest-v1）。
     *
     * @param string $raw
     * @return array
     * @throws Exception
     */
    public static function parseManifest($raw)
    {
        $raw = str_replace(["\r\n", "\r"], "\n", (string)$raw);
        $lines = explode("\n", trim($raw));
        $magic = array_shift($lines);
        if ($magic !== self::MANIFEST_MAGIC) {
            throw new Exception('Addon manifest format invalid');
        }
        $fields = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $pos = strpos($line, '=');
            if ($pos === false) {
                throw new Exception('Addon manifest format invalid');
            }
            $fields[trim(substr($line, 0, $pos))] = trim(substr($line, $pos + 1));
        }
        return $fields;
    }

    /**
     * 已安装插件的版本号（用于拒绝降级重放）。
     *
     * @param string $name
     * @return string
     */
    private static function installedVersion($name)
    {
        $candidates = [];
        if (defined('ADDON_PATH')) {
            $candidates[] = ADDON_PATH . $name . '/info.ini';
        }
        if (defined('ROOT_PATH')) {
            $candidates[] = ROOT_PATH . 'addons/' . $name . '/info.ini';
        }
        foreach ($candidates as $file) {
            if (is_file($file)) {
                $info = @parse_ini_file($file);
                if (is_array($info) && !empty($info['version'])) {
                    return (string)$info['version'];
                }
            }
        }
        return '';
    }

    /**
     * 清单验签与约束校验：keyid 可信 → 清单签名 → 名称/哈希/版本/有效期/防降级。
     *
     * @param string $file     插件包路径
     * @param string $name     期望的插件标识
     * @param array  $envelope parseEnvelope() 的结果
     * @param array  $config   包内 info.ini 解析结果
     * @return bool
     * @throws Exception
     */
    public static function verifyManifest($file, $name, array $envelope, $config = [])
    {
        $manifestRaw = self::decodeManifest($envelope['manifest'] ?? '');
        $fields = self::parseManifest($manifestRaw);

        $keyid = trim((string)($envelope['keyid'] ?? ''));
        if ($keyid === '') {
            throw new Exception('Addon manifest keyid missing');
        }
        if (trim((string)($fields['keyid'] ?? '')) !== $keyid) {
            throw new Exception('Addon manifest keyid mismatch');
        }
        if (in_array($keyid, self::revokedKeyIds(), true)) {
            throw new Exception(__('Addon signature key revoked: %s', $keyid));
        }

        $keys = self::keyRing();
        if (!isset($keys[$keyid])) {
            throw new Exception(__('Addon signature key not trusted: %s', $keyid));
        }
        $pem = self::loadPublicKey($keys[$keyid]);
        if ($pem === '') {
            throw new Exception('Addon signature public key unavailable');
        }

        $sig = base64_decode(preg_replace('/\s+/', '', (string)$envelope['sig']), true);
        if ($sig === false) {
            $sig = (string)$envelope['sig'];
        }
        if (openssl_verify($manifestRaw, $sig, $pem, OPENSSL_ALGO_SHA256) !== 1) {
            throw new Exception('Addon manifest signature verification failed');
        }

        // 签名通过之后才信任清单中的字段
        if ((string)($fields['name'] ?? '') !== $name) {
            throw new Exception('Addon manifest name mismatch');
        }
        $sha = strtolower(trim((string)($fields['sha256'] ?? '')));
        if (!preg_match('/^[a-f0-9]{64}$/', $sha) || !hash_equals($sha, (string)hash_file('sha256', $file))) {
            throw new Exception('Addon package digest mismatch');
        }
        $version = trim((string)($fields['version'] ?? ''));
        if ($version === '') {
            throw new Exception('Addon manifest version missing');
        }
        $infoVersion = trim((string)($config['version'] ?? ''));
        if ($infoVersion !== '' && version_compare($version, $infoVersion, '!=')) {
            throw new Exception('Addon manifest version mismatch');
        }

        $skew = (int)config('fastadmin.addon_sign_clock_skew');
        $skew = $skew > 0 ? $skew : 300;

        $expires = trim((string)($fields['expires_at'] ?? ''));
        if ($expires === '') {
            throw new Exception('Addon manifest expiry missing');
        }
        $expiresTs = strtotime($expires);
        if ($expiresTs === false) {
            throw new Exception('Addon manifest expiry invalid');
        }
        if ($expiresTs + $skew < time()) {
            throw new Exception('Addon package signature expired');
        }
        $issued = trim((string)($fields['issued_at'] ?? ''));
        if ($issued !== '') {
            $issuedTs = strtotime($issued);
            if ($issuedTs === false) {
                throw new Exception('Addon manifest issued_at invalid');
            }
            if ($issuedTs - $skew > time()) {
                throw new Exception('Addon package signature not yet valid');
            }
        }

        // 防降级重放：清单版本不得低于站点已安装版本
        if (!config('fastadmin.addon_sign_allow_downgrade')) {
            $installed = self::installedVersion($name);
            if ($installed !== '' && version_compare($version, $installed, '<')) {
                throw new Exception(__('Addon downgrade rejected: %s < %s', $version, $installed));
            }
        }
        return true;
    }

    /**
     * 校验压缩包条目路径，阻断 zip-slip / 绝对路径 / 空字节。
     *
     * @param ZipFile $zip
     * @return bool
     * @throws Exception
     */
    public static function assertSafeArchive(ZipFile $zip)
    {
        foreach ($zip->getListFiles() as $entry) {
            $path = str_replace('\\', '/', (string)$entry);
            if ($path === '' || strpos($path, "\0") !== false) {
                throw new Exception('Unsafe path in addon package');
            }
            if ($path[0] === '/' || preg_match('/^[A-Za-z]:/', $path)) {
                throw new Exception('Absolute path in addon package');
            }
            foreach (explode('/', $path) as $segment) {
                if ($segment === '..') {
                    throw new Exception('Path traversal in addon package');
                }
            }
        }
        return true;
    }

    /**
     * 禁止把插件 public/ 目录中的可执行脚本复制到站点根目录。
     *
     * @param string $dir      插件内的目录绝对路径
     * @param string $dirName  目录标识（application/public）
     * @return bool
     * @throws Exception
     */
    public static function assertSafePublicDir($dir, $dirName = '')
    {
        if ($dirName !== 'public' || !is_dir($dir)) {
            return true;
        }
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
        );
        foreach ($iterator as $fileinfo) {
            if ($fileinfo->isFile() && preg_match('/\.(php|phtml|phar|php\d+|inc|htaccess)$/i', $fileinfo->getFilename())) {
                throw new Exception('Executable file in addon public directory is not allowed');
            }
        }
        return true;
    }

    /**
     * install.sql / upgrade.sql 受控迁移白名单。
     *
     * @param string $sql
     * @return bool
     * @throws Exception
     */
    public static function assertSafeSql($sql)
    {
        // 去掉块注释与行注释后判断（# 仅按“行首注释”处理，避免误伤字符串中的 #）
        $clean = preg_replace('/\/\*.*?\*\//s', '', (string)$sql);
        $clean = preg_replace('/^[ \t]*#[^\n]*$/m', '', $clean);
        $clean = trim(preg_replace('/^\s*--.*$/m', '', $clean));
        if ($clean === '') {
            return true;
        }
        $oneLine = preg_replace('/\s+/', ' ', $clean);

        // DDL/DML + 事务控制 + 会话内动态 SQL（SET @var / PREPARE / EXECUTE / DEALLOCATE）
        $allowed = '/^(CREATE\s+(?:TABLE|(?:UNIQUE\s+)?INDEX)|INSERT\s+(?:IGNORE\s+)?INTO|REPLACE\s+INTO|UPDATE\b|'
            . 'DELETE\s+FROM|ALTER\s+TABLE|DROP\s+(?:TABLE\s+IF\s+EXISTS|INDEX)|'
            . 'SET\b|START\s+TRANSACTION\b|BEGIN\b|COMMIT\b|ROLLBACK\b|'
            . 'PREPARE\b|EXECUTE\b|DEALLOCATE\b)/i';
        if (!preg_match($allowed, $oneLine)) {
            throw new Exception(__('Unsafe SQL statement in addon install script: %s', self::sqlPreview($oneLine)));
        }

        // 危险构造：文件读写、权限/账号变更、全局与会话变量篡改、存储过程与触发器、系统库直读。
        // 注意：动态 SQL 的字符串字面量同样落在 $oneLine 中，因此 'DROP DATABASE' 之类仍会被此规则拦下。
        $blocked = '/\b(INTO\s+(?:OUT|DUMP)FILE|LOAD\s+DATA\s+LOCAL\s+INFILE|GRANT\b|REVOKE\b|CALL\b|'
            . 'SET\s+(?:GLOBAL|SESSION|@@)|CREATE\s+(?:TRIGGER|FUNCTION|PROCEDURE|VIEW|DATABASE|USER)|'
            . 'DROP\s+(?:DATABASE|USER|TRIGGER|FUNCTION|PROCEDURE|VIEW)|mysql\.)/i';
        if (preg_match($blocked, $oneLine, $m)) {
            throw new Exception(__('Unsafe SQL statement in addon install script (%s): %s', trim($m[0]), self::sqlPreview($oneLine)));
        }
        return true;
    }

    /**
     * 截取语句头部，便于定位被拦截的迁移语句。
     *
     * @param string $sql
     * @param int    $length
     * @return string
     */
    private static function sqlPreview($sql, $length = 120)
    {
        $sql = preg_replace('/\s+/', ' ', trim((string)$sql));
        return mb_strlen($sql) > $length ? mb_substr($sql, 0, $length) . '...' : $sql;
    }

    /**
     * 插件包强制校验入口。必须在 unzip() 与任何 new $addonClass() 之前调用。
     *
     * @param string $file      插件包绝对路径
     * @param string $name      插件标识（可选，缺省从 info.ini 读取）
     * @param string $signature 签名：裸 base64，或 buildEnvelopeEncoded() 生成的 JSON 信封；
     *                          缺省时取本次请求内 registerSignature() 登记的签名；
     *                          本地安装（$extend['local_endorsed']）无签名时改用 addon_sign_local_pins
     *                          中官网签发的信封，仍然执行完整的清单验签
     * @param array  $extend    安装扩展参数（uid/token/version 等）
     * @return bool
     * @throws Exception
     */
    public static function verifyPackage($file, $name = '', $signature = '', $extend = [])
    {
        if (!is_file($file)) {
            throw new Exception('Addon package not found');
        }
        $real = realpath($file);
        $keys = self::keyRing();

        $size = filesize($file);
        if ($size <= 0 || $size > 102400000) {
            throw new Exception('Invalid addon package size');
        }

        // 本地静态校验：包可打开、条目路径安全、info.ini 可解析
        $config = [];
        $comment = '';
        $zip = new ZipFile();
        try {
            $zip->openFile($file);
            self::assertSafeArchive($zip);
            try {
                $info = $zip->getEntryContents('info.ini');
                $config = (array)parse_ini_string((string)$info);
            } catch (\Throwable $e) {
                // info.ini 缺失时交由后续名称校验拒绝
            }
            $comment = (string)$zip->getArchiveComment();
        } finally {
            $zip->close();
        }

        $name = $name ?: (string)($config['name'] ?? '');
        if ($name === '' || !preg_match('/^[a-zA-Z0-9]+$/', $name)) {
            throw new Exception('Addon name incorrect');
        }

        // 签名只接受调用方显式传入（下载响应），或同一请求内 download() 登记的签名
        if (trim((string)$signature) === '') {
            $signatureKey = $real ?: $file;
            if (isset(self::$signatures[$signatureKey])) {
                $signature = self::$signatures[$signatureKey];
            }
        }

        // 缓存键覆盖签名、密钥环、本地签名包、吊销列表、降级策略与已安装版本，任一变更立即失效
        $pinSignatures = self::localPinSignatures($name);
        $cacheKey = ($real ?: $file) . ':' . filesize($file) . ':' . filemtime($file) . ':' . md5(
            $signature
            . '|' . json_encode($keys)
            . '|' . json_encode(self::revokedKeyIds())
            . '|' . implode(',', $pinSignatures)
            . '|' . (config('fastadmin.addon_sign_allow_downgrade') ? '1' : '0')
            . '|' . (!empty($extend['local_endorsed']) ? '1' : '0')
            . '|' . self::installedVersion($name)
        );
        if (isset(self::$verified[$cacheKey])) {
            return true;
        }

        $envelope = self::parseEnvelope($signature);
        $hasSignature = trim((string)$signature) !== '';
        $isLocal = !empty($extend['local_endorsed']);

        if ($keys) {
            // 本地安装未随请求带来签名：改用向官方申请并下载的签名信封，
            // 与远程安装走完全相同的清单验签，不存在「跳过验签」的放行分支
            if (!$hasSignature && $isLocal) {
                $ok = self::verifyWithLocalPins($file, $name, $config);
                self::$verified[$cacheKey] = true;
                return $ok;
            }
            // 本地公钥验签模式（强校验）
            if (!$hasSignature) {
                throw new Exception('Addon package signature missing');
            }
            if ($envelope !== null) {
                self::verifyManifest($file, $name, $envelope, $config);
            } else {
                // 裸签名：对 zip 原始字节验签，按公钥环逐个尝试（跳过已吊销 keyid）
                $normalized = preg_replace('/\s+/', '', (string)$signature);
                $raw = base64_decode($normalized, true);
                if ($raw === false) {
                    $raw = (string)$signature;
                }
                $payload = (string)file_get_contents($file);
                $revoked = self::revokedKeyIds();
                $matched = false;
                foreach ($keys as $id => $value) {
                    if (in_array($id, $revoked, true)) {
                        continue;
                    }
                    $keyContent = self::loadPublicKey($value);
                    if ($keyContent === '') {
                        continue;
                    }
                    if (openssl_verify($payload, $raw, $keyContent, OPENSSL_ALGO_SHA256) === 1) {
                        $matched = true;
                        break;
                    }
                }
                if (!$matched) {
                    throw new Exception('Addon package signature verification failed');
                }
            }
        } else {
            // 服务端验证模式：md5 经由已校验 TLS 的官方 API 判定
            $mysqlVersion = '';
            try {
                $row = Db::query('SELECT version() AS version');
                $mysqlVersion = $row[0]['version'] ?? '';
            } catch (\Throwable $e) {
                // 数据库不可用时继续，由服务端判定
            }
            $params = array_merge($config, (array)$extend, [
                'name'           => $name,
                'md5'            => md5_file($file),
                'sha256'         => hash_file('sha256', $file),
                'data'           => $comment,
                'version'        => (string)($config['version'] ?? ($extend['version'] ?? '')),
                'oldversion'     => (string)($extend['oldversion'] ?? ''),
                'unknownsources' => config('app_debug') && config('fastadmin.unknownsources'),
                'faversion'      => config('fastadmin.version'),
                'phpversion'     => PHP_VERSION,
                'mysqlversion'   => $mysqlVersion,
            ]);
            if (!Service::valid($params)) {
                throw new Exception('Addon package validation failed');
            }
        }

        self::$verified[$cacheKey] = true;
        return true;
    }
}
