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
 *      或官方 API 的 /addon/valid 做 md5 背书；
 *   3. 落地执行：install.sql 受控迁移白名单，禁止 public/ 目录可执行脚本复制到站点根。
 */
class Security
{
    /** @var array 已校验通过的包缓存，避免同一请求内重复远端校验 */
    private static $verified = [];

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

        // 限制自动重定向，避免校验后的请求被重定向到非受信主机
        $options['allow_redirects'] = [
            'max'     => 3,
            'strict'  => true,
            'referer' => false,
        ];

        return $options;
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
        // 去掉块注释与行注释后判断
        $clean = preg_replace('/\/\*.*?\*\//s', '', (string)$sql);
        $clean = trim(preg_replace('/^\s*--.*$/m', '', $clean));
        if ($clean === '') {
            return true;
        }
        $oneLine = preg_replace('/\s+/', ' ', $clean);

        $allowed = '/^(CREATE\s+(?:TABLE|(?:UNIQUE\s+)?INDEX)|INSERT\s+(?:IGNORE\s+)?INTO|REPLACE\s+INTO|UPDATE\b|DELETE\s+FROM|ALTER\s+TABLE|DROP\s+(?:TABLE\s+IF\s+EXISTS|INDEX)|SET\b)/i';
        if (!preg_match($allowed, $oneLine)) {
            throw new Exception('Unsafe SQL statement in addon install script');
        }

        $blocked = '/\b(INTO\s+(?:OUT|DUMP)FILE|LOAD\s+DATA\s+LOCAL\s+INFILE|GRANT\b|REVOKE\b|CALL\b|SET\s+(?:GLOBAL|SESSION|@@)|CREATE\s+(?:TRIGGER|FUNCTION|PROCEDURE|VIEW|DATABASE|USER)|DROP\s+(?:DATABASE|USER|TRIGGER|FUNCTION|PROCEDURE|VIEW)|INFORMATION_SCHEMA\b|mysql\.)/i';
        if (preg_match($blocked, $oneLine)) {
            throw new Exception('Unsafe SQL statement in addon install script');
        }
        return true;
    }

    /**
     * 插件包强制校验入口。必须在 unzip() 与任何 new $addonClass() 之前调用。
     *
     * @param string $file      插件包绝对路径
     * @param string $name      插件标识（可选，缺省从 info.ini 读取）
     * @param string $signature 下载响应中的签名（可选）
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
        $cacheKey = ($real ?: $file) . ':' . filesize($file) . ':' . filemtime($file);
        if (isset(self::$verified[$cacheKey])) {
            return true;
        }

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

        $publicKey = trim((string)config('fastadmin.addon_sign_public_key'));
        if ($publicKey !== '') {
            // 本地公钥验签模式（强校验）
            $keyContent = is_file($publicKey) ? @file_get_contents($publicKey) : $publicKey;
            if (!$keyContent) {
                throw new Exception('Addon signature public key unavailable');
            }
            if ($signature === '' && is_file($file . '.sig')) {
                $signature = (string)@file_get_contents($file . '.sig');
            }
            if ($signature === '') {
                throw new Exception('Addon package signature missing');
            }
            // 规范化 base64（容忍 PEM/换行包裹的写法），解码失败则按原始二进制处理
            $normalized = preg_replace('/\s+/', '', (string)$signature);
            $raw = base64_decode($normalized, true);
            if ($raw === false) {
                $raw = (string)$signature;
            }
            $result = openssl_verify((string)file_get_contents($file), $raw, $keyContent, OPENSSL_ALGO_SHA256);
            if ($result !== 1) {
                throw new Exception('Addon package signature verification failed');
            }
        } else {
            // 服务端背书模式：md5 经由已校验 TLS 的官方 API 判定
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
