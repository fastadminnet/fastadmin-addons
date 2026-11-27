<?php

namespace think\addons;

use fast\Http;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\TransferStats;
use PhpZip\Exception\ZipException;
use PhpZip\ZipFile;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use think\Cache;
use think\Config;
use think\Db;
use think\Exception;
use think\Log;

/**
 * 插件服务
 * @package think\addons
 */
class Service
{
    /**
     * 插件列表
     */
    public static function addons($params = [])
    {
        $params['domain'] = request()->host(true);
        return self::sendRequest('/addon/index', $params, 'GET');
    }

    /**
     * 检测插件是否购买授权
     */
    public static function isBuy($name, $extend = [])
    {
        $params = array_merge(['name' => $name, 'domain' => request()->host(true)], $extend);
        return self::sendRequest('/addon/isbuy', $params, 'POST');
    }

    /**
     * 检测插件是否授权
     *
     * @param string $name   插件名称
     * @param string $domain 验证域名
     */
    public static function isAuthorization($name, $domain = '')
    {
        $config = self::config($name);
        $request = request();
        $domain = self::getRootDomain($domain ? $domain : $request->host(true));
        if (isset($config['domains']) && isset($config['validations']) && isset($config['licensecodes'])) {
            $index = array_search($domain, $config['domains']);
            if ((in_array($domain, $config['domains']) && in_array(md5(md5($domain) . ($config['licensecodes'][$index] ?? '')), $config['validations'])) || $request->isCli()) {
                return true;
            }
        }
        return false;
    }

    /**
     * 远程下载插件
     *
     * @param string $name   插件名称
     * @param array  $extend 扩展参数
     * @return  string
     */
    public static function download($name, $extend = [])
    {
        $addonsTempDir = self::getAddonsBackupDir();
        $tmpFile = $addonsTempDir . $name . ".zip";
        $signature = '';
        $keyid = '';
        $manifest = '';
        try {
            $client = self::getClient();
            Security::resetHopHeaders();
            $response = $client->get('/addon/download', ['query' => array_merge(['name' => $name], $extend)]);
            $body = $response->getBody();
            $content = $body->getContents();

            if (substr($content, 0, 1) === '{') {
                $json = (array)json_decode($content, true);
                //如果传回的是一个下载链接,则再次下载
                if (!empty($json['data']) && isset($json['data']['url'])) {
                    // [SECURITY] 仅允许跟随到受信域名
                    Security::assertTrustedUrl($json['data']['url']);
                    $response = $client->get($json['data']['url']);
                    $body = $response->getBody();
                    $content = $body->getContents();

                    $signature = (string)$response->getHeaderLine('X-Addon-Signature');
                    $keyid = (string)$response->getHeaderLine('X-Addon-Keyid');
                    $manifest = (string)$response->getHeaderLine('X-Addon-Manifest');

                    $signature = (string)($json['data']['signature'] ?? $signature);
                    $keyid = (string)($json['data']['keyid'] ?? $keyid);
                    $manifest = (string)($json['data']['manifest'] ?? $manifest);
                } else {
                    //下载返回错误，抛出异常
                    throw new AddonException($json['msg'] ?? '', $json['code'] ?? 0, $json['data'] ?? '');
                }
            }

            // 兼容 /addon/download 直接返回二进制包的形态：签名随本次响应头下发
            if ($signature === '') {
                $signature = (string)$response->getHeaderLine('X-Addon-Signature');
            }
            if ($keyid === '') {
                $keyid = (string)$response->getHeaderLine('X-Addon-Keyid');
            }
            if ($manifest === '') {
                $manifest = (string)$response->getHeaderLine('X-Addon-Manifest');
            }

            // 兼容 /addon/download 以 3xx 重定向到资源地址的形态：签名挂在重定向响应头里，
            // 最终响应（CDN 静态文件）通常不带签名头，此处按需回填
            $hop = Security::hopHeaders();
            $signature = $signature !== '' ? $signature : (string)($hop['signature'] ?? '');
            $keyid = $keyid !== '' ? $keyid : (string)($hop['keyid'] ?? '');
            $manifest = $manifest !== '' ? $manifest : (string)($hop['manifest'] ?? '');
        } catch (TransferException $e) {
            throw new Exception("Addon package download failed");
        }

        if ($write = fopen($tmpFile, 'w')) {
            fwrite($write, $content);
            fclose($write);
        } else {
            throw new Exception("No permission to write temporary files");
        }

        // [SECURITY] 解压与实例化之前强制校验插件包完整性/真实性
        // 服务端返回 keyid + base64(清单) 时组装为签名信封，交由 verifyManifest() 做密钥选择与清单约束校验
        $envelope = Security::buildEnvelopeEncoded($signature, $keyid, $manifest);
        Security::verifyPackage($tmpFile, $name, $envelope, $extend);
        // 签名不落盘：校验通过后仅在当前请求内登记，供 install()/upgrade() 的二次校验复用
        Security::registerSignature($tmpFile, $envelope);
        return $tmpFile;
    }

    /**
     * 解压插件
     *
     * @param string $name 插件名称
     * @param string $file 文件路径
     * @return  string
     * @throws  Exception
     */
    public static function unzip($name, $file = '')
    {
        if (!$name || !preg_match("/^[a-zA-Z0-9]+$/", $name)) {
            throw new Exception('Invalid parameters');
        }
        $addonsBackupDir = self::getAddonsBackupDir();
        $file = $file ?: $addonsBackupDir . $name . '.zip';

        // 打开插件压缩包
        $zip = new ZipFile();
        try {
            $zip->openFile($file);
        } catch (ZipException $e) {
            $zip->close();
            throw new Exception('Unable to open the zip file');
        }

        // [SECURITY] 阻止 zip-slip / 绝对路径写入
        Security::assertSafeArchive($zip);

        $dir = self::getAddonDir($name);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755);
        }

        // 解压插件压缩包
        try {
            $zip->extractTo($dir);
        } catch (ZipException $e) {
            throw new Exception('Unable to extract the file');
        } finally {
            $zip->close();
        }
        return $dir;
    }

    /**
     * 离线安装
     * @param string $file   插件压缩包
     * @param array  $extend 扩展参数
     * @param string $force  是否覆盖
     */
    public static function local($file, $extend = [], $force = false)
    {
        $addonsTempDir = self::getAddonsBackupDir();
        if (!$file || !$file instanceof \think\File) {
            throw new Exception('No file upload or server upload limit exceeded');
        }
        $uploadFile = $file->rule('uniqid')->validate(['size' => 102400000, 'ext' => 'zip,fastaddon'])->move($addonsTempDir);
        if (!$uploadFile) {
            // 上传失败获取错误信息
            throw new Exception(__($file->getError()));
        }
        $tmpFile = $addonsTempDir . $uploadFile->getSaveName();

        $info = [];
        $zip = new ZipFile();
        try {

            // 打开插件压缩包
            try {
                $zip->openFile($tmpFile);
            } catch (ZipException $e) {
                @unlink($tmpFile);
                throw new Exception('Unable to open the zip file');
            }

            $config = self::getInfoIni($zip);

            // 判断插件标识
            $name = $config['name'] ?? '';
            if (!$name) {
                throw new Exception('Addon info file data incorrect');
            }

            // 判断插件是否存在
            if (!preg_match("/^[a-zA-Z0-9]+$/", $name)) {
                throw new Exception('Addon name incorrect');
            }

            // 判断新插件是否存在
            $newAddonDir = self::getAddonDir($name);
            if (!$force && is_dir($newAddonDir)) {
                throw new AddonException('Addon already exists', -1, ['name' => $name, 'title' => $config['title'] ?? '']);
            }

            // 读取旧版本号
            $oldversion = '';
            if (is_dir($newAddonDir)) {
                $oldConfig = parse_ini_file($newAddonDir . 'info.ini');
                $oldversion = $oldConfig['version'] ?? '';
            }

            $extend['oldversion'] = $oldversion;
            $extend['version'] = $config['version'] ?? '';

            // 追加MD5和Data数据
            $extend['md5'] = md5_file($tmpFile);
            $extend['data'] = $zip->getArchiveComment();
            $extend['unknownsources'] = config('app_debug') && config('fastadmin.unknownsources');
            $extend['faversion'] = config('fastadmin.version');
            $extend['phpversion'] = PHP_VERSION;
            $mysqlVersion = Db::query('SELECT version() AS version');
            $extend['mysqlversion'] = $mysqlVersion[0]['version'] ?? '';

            // 补全签名清单所需参数：服务端据此回传本包签名（keyid/manifest/sign），
            // 使本地安装与远程安装共用同一套清单验签
            $extend['sha256'] = hash_file('sha256', $tmpFile);

            $params = array_merge($config, $extend);

            // 压缩包验证、版本依赖判断，应用插件需要授权使用，移除或绕过授权验证，保留追究法律责任的权利
            // 验证通过后服务端在 data 段回传本包签名（manifest 恒为 base64），客户端据此完成强制验签
            $validData = [];
            Service::valid($params, $validData);
            $envelope = Security::buildEnvelopeEncoded(
                (string)($validData['signature'] ?? ''),
                (string)($validData['keyid'] ?? ''),
                (string)($validData['manifest'] ?? '')
            );
            if ($envelope !== '') {
                // 签名只在当前请求内登记，供 install()/upgrade() 的二次校验复用
                Security::registerSignature($tmpFile, $envelope);
            }
            // 标记：本地上传安装上下文，供 Security::verifyPackage() 在无签名时取用官网签发的信封
            $extend['local_endorsed'] = true;

            if (!$oldversion) {
                // 新装模式
                $info = Service::install($name, $force, $extend, $tmpFile);
            } else {
                // 升级模式
                $info = Service::upgrade($name, $extend, $tmpFile);
            }

        } catch (AddonException $e) {
            throw new AddonException($e->getMessage(), $e->getCode(), $e->getData());
        } catch (Exception $e) {
            throw new Exception(__($e->getMessage()));
        } finally {
            $zip->close();
            unset($uploadFile);
            is_file($tmpFile) && unlink($tmpFile);
        }

        $info['config'] = get_addon_config($name) ? 1 : 0;
        $info['bootstrap'] = is_file(Service::getBootstrapFile($name));
        $info['testdata'] = is_file(Service::getTestdataFile($name));
        return $info;
    }

    /**
     * 验证压缩包、依赖验证
     *
     * 服务端在验证通过后于 data 段回传本包签名，本地安装据此做强制验签
     * （与远程下载返回的签名结构一致，客户端共用同一套清单验签）：
     *   data.signature              清单签名（base64）
     *   data.keyid                  签发密钥标识
     *   data.manifest               签名清单原文（addon-manifest-v1，需 base64）
     *
     * @param array $params   验证参数（name/version/md5/sha256/data/faversion/phpversion 等）
     * @param array $response 出参：服务端返回的 data 段
     * @return bool
     * @throws Exception
     */
    public static function valid($params = [], &$response = null)
    {
        $json = self::sendRequest('/addon/valid', $params, 'POST');
        if ($json && isset($json['code'])) {
            if ($json['code']) {
                $response = isset($json['data']) && is_array($json['data']) ? $json['data'] : [];
                return true;
            } else {
                throw new Exception($json['msg'] ?? "Invalid addon package");
            }
        } else {
            throw new Exception("Unknown data format");
        }
    }

    /**
     * 备份插件
     * @param string $name 插件名称
     * @return bool
     * @throws Exception
     */
    public static function backup($name)
    {
        $addonsBackupDir = self::getAddonsBackupDir();
        $file = $addonsBackupDir . $name . '-backup-' . date("YmdHis") . '.zip';
        $zipFile = new ZipFile();
        try {
            $zipFile
                ->addDirRecursive(self::getAddonDir($name))
                ->saveAsFile($file)
                ->close();
        } catch (ZipException $e) {

        } finally {
            $zipFile->close();
        }

        return true;
    }

    /**
     * 检测插件是否完整
     *
     * @param string $name 插件名称
     * @return  boolean
     * @throws  Exception
     */
    public static function check($name)
    {
        if (!$name || !is_dir(ADDON_PATH . $name)) {
            throw new Exception('Addon not exists');
        }
        $addonClass = get_addon_class($name);
        if (!$addonClass) {
            throw new Exception("The addon file does not exist");
        }
        $addon = new $addonClass();
        if (!$addon->checkInfo()) {
            throw new Exception("The configuration file content is incorrect");
        }
        // 检测环境
        if (method_exists($addon, 'checkEnv')) {
            $addon->checkEnv();
        }
        return true;
    }

    /**
     * 是否有冲突
     *
     * @param string $name 插件名称
     * @return  boolean
     * @throws  AddonException
     */
    public static function noconflict($name)
    {
        // 检测冲突文件
        $list = self::getGlobalFiles($name, true);
        if ($list) {
            //发现冲突文件，抛出异常
            throw new AddonException(__("Conflicting file found"), -3, ['conflictlist' => $list]);
        }
        return true;
    }

    /**
     * 导入SQL
     *
     * @param string $name     插件名称
     * @param string $fileName SQL文件名称
     * @return  boolean
     */
    public static function importsql($name, $fileName = null)
    {
        $fileName = is_null($fileName) ? 'install.sql' : $fileName;
        $sqlFile = self::getAddonDir($name) . $fileName;
        if (is_file($sqlFile)) {
            $lines = file($sqlFile);
            $templine = '';
            foreach ($lines as $line) {
                $trimmed = ltrim($line);
                // 跳过空行与各类注释行（-- / # / /*），否则注释会被拼进下一条语句导致白名单误判
                if (trim($line) === '' || substr($trimmed, 0, 2) == '--'
                    || substr($trimmed, 0, 1) == '#' || substr($trimmed, 0, 2) == '/*') {
                    continue;
                }

                $templine .= $line;
                // 兼容 “;  # 行尾注释” 的写法
                if (substr(trim($line), -1, 1) == ';' || preg_match('/;\s*#.*$/', $line)) {
                    $templine = str_ireplace('__PREFIX__', config('database.prefix'), $templine);
                    $templine = str_ireplace('INSERT INTO ', 'INSERT IGNORE INTO ', $templine);
                    // [SECURITY] 仅执行受控的迁移语句，阻断文件/权限/存储过程等危险构造
                    Security::assertSafeSql($templine);
                    try {
                        Db::getPdo()->exec($templine);
                    } catch (\PDOException $e) {
                        //$e->getMessage();
                    }
                    $templine = '';
                }
            }
        }
        return true;
    }

    /**
     * 刷新插件缓存文件
     *
     * @return  boolean
     * @throws  Exception
     */
    public static function refresh()
    {
        //刷新addons.js
        $addons = get_addon_list();
        $bootstrapArr = [];
        foreach ($addons as $name => $addon) {
            $bootstrapFile = self::getBootstrapFile($name);
            if ($addon['state'] && is_file($bootstrapFile)) {
                $bootstrapArr[] = file_get_contents($bootstrapFile);
            }
        }
        $addonsFile = ROOT_PATH . str_replace("/", DS, "public/assets/js/addons.js");
        if ($handle = fopen($addonsFile, 'w')) {
            $tpl = <<<EOD
define([], function () {
    {__JS__}
});
EOD;
            fwrite($handle, str_replace("{__JS__}", implode("\n", $bootstrapArr), $tpl));
            fclose($handle);
        } else {
            throw new Exception(__("Unable to open file '%s' for writing", "addons.js"));
        }

        Cache::rm("addons");
        Cache::rm("hooks");

        $file = self::getExtraAddonsFile();

        $config = get_addon_autoload_config(true);
        if (!empty($config['autoload'])) {
            return;
        }

        if (!is_really_writable($file)) {
            throw new Exception(__("Unable to open file '%s' for writing", "addons.php"));
        }

        file_put_contents($file, "<?php\n\n" . "return " . var_export_short($config, true) . ";\n", LOCK_EX);
        return true;
    }

    /**
     * 补全运行环境参数
     *
     * @param array $extend 扩展参数
     * @return array
     */
    protected static function addEnvironmentParams(array $extend = [])
    {
        $extend['domain'] = request()->host(true);
        $extend['phpversion'] = PHP_VERSION;
        $extend['thinkversion'] = defined('THINK_VERSION') ? THINK_VERSION : '';
        $mysqlVersion = Db::query('SELECT version() AS version');
        $extend['mysqlversion'] = $mysqlVersion[0]['version'] ?? '';
        return $extend;
    }

    /**
     * 安装插件
     *
     * @param string  $name    插件名称
     * @param boolean $force   是否覆盖
     * @param array   $extend  扩展参数
     * @param array   $tmpFile 本地文件
     * @return  boolean
     * @throws  Exception
     * @throws  AddonException
     */
    public static function install($name, $force = false, $extend = [], $tmpFile = '')
    {
        if (!$name || (is_dir(ADDON_PATH . $name) && !$force)) {
            throw new Exception('Addon already exists');
        }

        $extend = self::addEnvironmentParams($extend);

        // 远程下载插件
        $tmpFile = $tmpFile ?: Service::download($name, $extend);

        // [SECURITY] 解压/实例化之前强制验包（本地安装包同样覆盖）
        // 远程安装复用 download() 在内存中登记的签名；本地安装包无签名，由 local_endorsed 兜底
        Security::verifyPackage($tmpFile, $name, '', $extend);

        $addonDir = self::getAddonDir($name);

        try {
            // 解压插件压缩包到插件目录
            Service::unzip($name, $tmpFile);

            // 检查插件是否完整
            Service::check($name);

            if (!$force) {
                Service::noconflict($name);
            }
        } catch (AddonException $e) {
            @rmdirs($addonDir);
            throw new AddonException($e->getMessage(), $e->getCode(), $e->getData());
        } catch (Exception $e) {
            @rmdirs($addonDir);
            throw new Exception($e->getMessage());
        } finally {
            // 移除临时文件
            @unlink($tmpFile);
        }

        // 默认启用该插件
        $info = get_addon_info($name);

        Db::startTrans();
        try {
            if (empty($info['state'])) {
                $info['state'] = 1;
                set_addon_info($name, $info);
            }

            // 执行安装脚本
            $class = get_addon_class($name);
            if (class_exists($class)) {
                $addon = new $class();
                $addon->install();
            }
            Db::commit();
        } catch (Exception $e) {
            @rmdirs($addonDir);
            Db::rollback();
            throw new Exception($e->getMessage());
        }

        // 导入
        Service::importsql($name);

        // 启用插件
        Service::enable($name, true);

        $info['config'] = get_addon_config($name) ? 1 : 0;
        $info['bootstrap'] = is_file(Service::getBootstrapFile($name));
        $info['testdata'] = is_file(Service::getTestdataFile($name));
        return $info;
    }

    /**
     * 是否禁止卸载插件
     *
     * 关闭调试模式（生产环境）时默认禁止卸载，避免误删插件文件与数据表；
     * 可通过 fastadmin.addon_uninstall_require_debug = false 关闭该限制。
     *
     * @return boolean
     */
    public static function isUninstallDisabled()
    {
        $requireDebug = config('fastadmin.addon_uninstall_require_debug');
        if ($requireDebug === null) {
            // 未配置时按“需要调试模式”处理，安全优先
            $requireDebug = true;
        }
        return (bool)$requireDebug && !config('app_debug');
    }

    /**
     * 卸载插件
     *
     * @param string  $name
     * @param boolean $force 是否强制卸载
     * @return  boolean
     * @throws  Exception
     */
    public static function uninstall($name, $force = false)
    {
        if (self::isUninstallDisabled()) {
            throw new Exception('Addon uninstall requires debug mode');
        }

        if (!$name || !is_dir(ADDON_PATH . $name)) {
            throw new Exception('Addon not exists');
        }

        if (!$force) {
            Service::noconflict($name);
        }

        // 移除插件全局资源文件
        if ($force) {
            $list = Service::getGlobalFiles($name);
            foreach ($list as $k => $v) {
                @unlink(ROOT_PATH . $v);
            }
        }

        // 执行卸载脚本
        try {
            $class = get_addon_class($name);
            if (class_exists($class)) {
                $addon = new $class();
                $addon->uninstall();
            }
        } catch (Exception $e) {
            throw new Exception($e->getMessage());
        }

        // 移除插件目录
        rmdirs(ADDON_PATH . $name);

        // 刷新
        Service::refresh();
        return true;
    }

    /**
     * 启用
     * @param string  $name  插件名称
     * @param boolean $force 是否强制覆盖
     * @return  boolean
     */
    public static function enable($name, $force = false)
    {
        if (!$name || !is_dir(ADDON_PATH . $name)) {
            throw new Exception('Addon not exists');
        }

        if (!$force) {
            Service::noconflict($name);
        }

        //备份冲突文件
        if (config('fastadmin.backup_global_files')) {
            $conflictFiles = self::getGlobalFiles($name, true);
            if ($conflictFiles) {
                $zip = new ZipFile();
                try {
                    foreach ($conflictFiles as $k => $v) {
                        $zip->addFile(ROOT_PATH . $v, $v);
                    }
                    $addonsBackupDir = self::getAddonsBackupDir();
                    $zip->saveAsFile($addonsBackupDir . $name . "-conflict-enable-" . date("YmdHis") . ".zip");
                } catch (Exception $e) {

                } finally {
                    $zip->close();
                }
            }
        }

        $addonDir = self::getAddonDir($name);
        $sourceAssetsDir = self::getSourceAssetsDir($name);
        $destAssetsDir = self::getDestAssetsDir($name);

        $files = self::getGlobalFiles($name);
        if ($files) {
            //刷新插件配置缓存
            Service::config($name, ['files' => $files]);
        }

        // 复制文件
        if (is_dir($sourceAssetsDir)) {
            copydirs($sourceAssetsDir, $destAssetsDir);
        }

        // 复制application和public到全局
        foreach (self::getCheckDirs() as $k => $dir) {
            if (is_dir($addonDir . $dir)) {
                // [SECURITY] 禁止把插件 public/ 中的可执行脚本复制到站点根目录
                Security::assertSafePublicDir($addonDir . $dir, $dir);
                copydirs($addonDir . $dir, ROOT_PATH . $dir);
            }
        }

        //插件纯净模式时将插件目录下的application、public和assets删除
        if (config('fastadmin.addon_pure_mode')) {
            // 删除插件目录已复制到全局的文件
            @rmdirs($sourceAssetsDir);
            foreach (self::getCheckDirs() as $k => $dir) {
                @rmdirs($addonDir . $dir);
            }
        }

        //执行启用脚本
        try {
            $class = get_addon_class($name);
            if (class_exists($class)) {
                $addon = new $class();
                if (method_exists($class, "enable")) {
                    $addon->enable();
                }
            }
        } catch (Exception $e) {
            throw new Exception($e->getMessage());
        }

        $info = get_addon_info($name);
        $info['state'] = 1;
        unset($info['url']);

        set_addon_info($name, $info);

        // 刷新
        Service::refresh();
        return true;
    }

    /**
     * 禁用
     *
     * @param string  $name  插件名称
     * @param boolean $force 是否强制禁用
     * @return  boolean
     * @throws  Exception
     */
    public static function disable($name, $force = false)
    {
        if (!$name || !is_dir(ADDON_PATH . $name)) {
            throw new Exception('Addon not exists');
        }

        $file = self::getExtraAddonsFile();
        if (!is_really_writable($file)) {
            throw new Exception(__("Unable to open file '%s' for writing", "addons.php"));
        }

        if (!$force) {
            Service::noconflict($name);
        }

        if (config('fastadmin.backup_global_files')) {
            //仅备份修改过的文件
            $conflictFiles = Service::getGlobalFiles($name, true);
            if ($conflictFiles) {
                $zip = new ZipFile();
                try {
                    foreach ($conflictFiles as $k => $v) {
                        $zip->addFile(ROOT_PATH . $v, $v);
                    }
                    $addonsBackupDir = self::getAddonsBackupDir();
                    $zip->saveAsFile($addonsBackupDir . $name . "-conflict-disable-" . date("YmdHis") . ".zip");
                } catch (Exception $e) {

                } finally {
                    $zip->close();
                }
            }
        }

        $config = Service::config($name);

        $addonDir = self::getAddonDir($name);
        //插件资源目录
        $destAssetsDir = self::getDestAssetsDir($name);

        // 移除插件全局文件
        $list = Service::getGlobalFiles($name);

        //插件纯净模式时将原有的文件复制回插件目录
        //当无法获取全局文件列表时也将列表复制回插件目录
        if (config('fastadmin.addon_pure_mode') || !$list) {
            if ($config && isset($config['files']) && is_array($config['files'])) {
                foreach ($config['files'] as $index => $item) {
                    //避免切换不同服务器后导致路径不一致
                    $item = str_replace(['/', '\\'], DS, $item);
                    //插件资源目录，无需重复复制
                    if (stripos($item, str_replace(ROOT_PATH, '', $destAssetsDir)) === 0) {
                        continue;
                    }
                    //检查目录是否存在，不存在则创建
                    $itemBaseDir = dirname($addonDir . $item);
                    if (!is_dir($itemBaseDir)) {
                        @mkdir($itemBaseDir, 0755, true);
                    }
                    if (is_file(ROOT_PATH . $item)) {
                        @copy(ROOT_PATH . $item, $addonDir . $item);
                    }
                }
                $list = $config['files'];
            }
            //复制插件目录资源
            if (is_dir($destAssetsDir)) {
                @copydirs($destAssetsDir, $addonDir . 'assets' . DS);
            }
        }

        $dirs = [];
        foreach ($list as $k => $v) {
            $file = ROOT_PATH . $v;
            $dirs[] = dirname($file);
            @unlink($file);
        }

        // 移除插件空目录
        $dirs = array_filter(array_unique($dirs));
        foreach ($dirs as $k => $v) {
            remove_empty_folder($v);
        }

        $info = get_addon_info($name);
        $info['state'] = 0;
        unset($info['url']);

        set_addon_info($name, $info);

        // 执行禁用脚本
        try {
            $class = get_addon_class($name);
            if (class_exists($class)) {
                $addon = new $class();

                if (method_exists($class, "disable")) {
                    $addon->disable();
                }
            }
        } catch (Exception $e) {
            throw new Exception($e->getMessage());
        }

        // 刷新
        Service::refresh();
        return true;
    }

    /**
     * 升级插件
     *
     * @param string $name   插件名称
     * @param array  $extend 扩展参数
     */
    public static function upgrade($name, $extend = [], $tmpFile = false)
    {
        $info = get_addon_info($name);
        if (!empty($info['state'])) {
            throw new Exception(__('Please disable addon first'));
        }
        $config = get_addon_config($name);
        if ($config) {
            //备份配置
        }

        // 升级链路必须携带旧版本号，服务端据此判断增量脚本与升级关系；
        // 调用方（如命令行）未传时回退为当前已安装版本
        if (!isset($extend['oldversion']) || $extend['oldversion'] === '') {
            $extend['oldversion'] = $info['version'] ?? '';
        }

        // 与 install() 保持一致：补全 domain/phpversion/mysqlversion
        // 否则 /addon/download 拿不到域名与环境信息，服务端会判为无效升级请求
        $extend = self::addEnvironmentParams($extend);

        // 远程下载插件(如果为本地文件则使用本地文件)
        $tmpFile = $tmpFile ? $tmpFile : Service::download($name, $extend);

        // [SECURITY] 解压/动态生成升级类之前强制验包
        // 远程升级复用 download() 在内存中登记的签名；本地升级包无签名，由 local_endorsed 兜底
        Security::verifyPackage($tmpFile, $name, '', $extend);

        // 备份插件文件
        Service::backup($name);

        $addonDir = self::getAddonDir($name);

        // 删除插件目录下的application和public
        $files = self::getCheckDirs();
        foreach ($files as $index => $file) {
            @rmdirs($addonDir . $file);
        }

        try {
            // 解压插件
            Service::unzip($name, $tmpFile);
        } catch (Exception $e) {
            throw new Exception($e->getMessage());
        } finally {
            // 移除临时文件
            @unlink($tmpFile);
        }

        if ($config) {
            $configFile = ADDON_PATH . $name . DS . 'config.php';
            $bakFile = ADDON_PATH . $name . DS . 'config_tmp.php';
            @copy($configFile, $bakFile);
            $fullConfig = include($bakFile);
            @unlink($bakFile);
            foreach ($fullConfig as $index => &$item) {
                if (isset($config[$item['name']])) {
                    $item['value'] = $config[$item['name']];
                }
            }
            // 更新配置
            set_addon_fullconfig($name, $fullConfig);
        }

        // 导入
        Service::importsql($name);

        // 执行升级脚本
        try {
            $addonName = ucfirst($name);
            //创建临时类用于调用升级的方法
            $sourceFile = $addonDir . $addonName . ".php";
            $destFile = $addonDir . $addonName . "Upgrade.php";

            $sourceContent = @file_get_contents($sourceFile);
            if ($sourceContent === false) {
                throw new Exception(__('Addon file not found: %s.php', $addonName));
            }

            $classContent = str_replace("class {$addonName} extends", "class {$addonName}Upgrade extends", $sourceContent);

            //创建临时的类文件
            file_put_contents($destFile, $classContent);

            $className = "\\addons\\" . $name . "\\" . $addonName . "Upgrade";
            $addon = new $className($name);

            //调用升级的方法
            if (method_exists($addon, "upgrade")) {
                $addon->upgrade();
            }

            //移除临时文件
            @unlink($destFile);
        } catch (Exception $e) {
            throw new Exception($e->getMessage());
        }

        // 刷新
        Service::refresh();

        //必须变更版本号：优先用调用方指定的目标版本，缺失时回读解压后的 info.ini
        $version = (string)($extend['version'] ?? '');
        if ($version === '') {
            $installedInfo = (array)get_addon_info($name);
            $version = (string)($installedInfo['version'] ?? '');
        }
        $info['version'] = $version !== '' ? $version : $info['version'];

        $info['config'] = get_addon_config($name) ? 1 : 0;
        $info['bootstrap'] = is_file(Service::getBootstrapFile($name));
        return $info;
    }

    /**
     * 读取或修改插件配置
     * @param string $name
     * @param array  $changed
     * @return array
     */
    public static function config($name, $changed = [])
    {
        $addonDir = self::getAddonDir($name);
        $addonConfigFile = $addonDir . '.addonrc';
        $config = [];
        if (is_file($addonConfigFile)) {
            $config = (array)json_decode(file_get_contents($addonConfigFile), true);
        }
        $config = array_merge($config, $changed);
        if ($changed) {
            file_put_contents($addonConfigFile, json_encode($config, JSON_UNESCAPED_UNICODE));
        }
        return $config;
    }

    /**
     * 获取插件在全局的文件
     *
     * @param string  $name         插件名称
     * @param boolean $onlyconflict 是否只返回冲突文件
     * @return  array
     */
    public static function getGlobalFiles($name, $onlyconflict = false)
    {
        $list = [];
        $addonDir = self::getAddonDir($name);
        $checkDirList = self::getCheckDirs();
        $checkDirList = array_merge($checkDirList, ['assets']);

        $assetDir = self::getDestAssetsDir($name);

        // 扫描插件目录是否有覆盖的文件
        foreach ($checkDirList as $k => $dirName) {
            //检测目录是否存在
            if (!is_dir($addonDir . $dirName)) {
                continue;
            }
            //匹配出所有的文件
            $files = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($addonDir . $dirName, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST
            );

            foreach ($files as $fileinfo) {
                if ($fileinfo->isFile()) {
                    $filePath = $fileinfo->getPathName();
                    //如果名称为assets需要做特殊处理
                    if ($dirName === 'assets') {
                        $path = str_replace(ROOT_PATH, '', $assetDir) . str_replace($addonDir . $dirName . DS, '', $filePath);
                    } else {
                        $path = str_replace($addonDir, '', $filePath);
                    }
                    if ($onlyconflict) {
                        $destPath = ROOT_PATH . $path;
                        if (is_file($destPath)) {
                            if (filesize($filePath) != filesize($destPath) || md5_file($filePath) != md5_file($destPath)) {
                                $list[] = $path;
                            }
                        }
                    } else {
                        $list[] = $path;
                    }
                }
            }
        }
        $list = array_filter(array_unique($list));
        return $list;
    }

    /**
     * 更新本地应用插件授权
     */
    public static function authorization($params = [])
    {
        $addonList = get_addon_list();
        $result = [];
        $domain = request()->host(true);
        $addons = [];
        foreach ($addonList as $name => $item) {
            $config = self::config($name);
            $addons[] = ['name' => $name, 'domains' => $config['domains'] ?? [], 'licensecodes' => $config['licensecodes'] ?? [], 'validations' => $config['validations'] ?? []];
        }
        $params = array_merge($params, [
            'faversion' => config('fastadmin.version'),
            'domain'    => $domain,
            'addons'    => $addons
        ]);
        $result = self::sendRequest('/addon/authorization', $params, 'POST');
        if (isset($result['code']) && $result['code'] == 1) {
            $json = $result['data']['addons'] ?? [];
            foreach ($addonList as $name => $item) {
                self::config($name, ['domains' => $json[$name]['domains'] ?? [], 'licensecodes' => $json[$name]['licensecodes'] ?? [], 'validations' => $json[$name]['validations'] ?? []]);
            }
            return true;
        } else {
            throw new Exception($result['msg'] ?? __('Network error'));
        }
    }

    /**
     * 验证插件授权，应用插件需要授权使用，移除或绕过授权验证，保留追究法律责任的权利
     * @param $name
     * @return bool
     */
    public static function checkAddonAuthorization($name)
    {
        $request = request();
        $config = self::config($name);
        $domain = self::getRootDomain($request->host(true));
        //应用插件需要授权使用，移除或绕过授权验证，保留追究法律责任的权利
        if (isset($config['domains']) && isset($config['validations']) && isset($config['licensecodes'])) {
            $index = array_search($domain, $config['domains']);
            if ((in_array($domain, $config['domains']) && in_array(md5(md5($domain) . ($config['licensecodes'][$index] ?? '')), $config['validations'])) || $request->isCli()) {
                $request->bind('authorized', $domain ?: 'cli');
                return true;
            } elseif ($config['domains']) {
                foreach ($config['domains'] as $index => $item) {
                    if (substr_compare($domain, "." . $item, -strlen("." . $item)) === 0 && in_array(md5(md5($item) . ($config['licensecodes'][$index] ?? '')), $config['validations'])) {
                        $request->bind('authorized', $domain);
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * 获取顶级域名
     * @param $domain
     * @return string
     */
    public static function getRootDomain($domain)
    {
        // PHP8.1 起 trim() 不接受 null（CLI 下 request()->host() 会返回 null）
        $host = strtolower(trim((string)$domain));
        $hostArr = explode('.', $host);
        $hostCount = count($hostArr);
        $cnRegex = '/\w+\.(gov|org|ac|mil|net|edu|com|bj|tj|sh|cq|he|sx|nm|ln|jl|hl|js|zj|ah|fj|jx|sd|ha|hb|hn|gd|gx|hi|sc|gz|yn|xz|sn|gs|qh|nx|xj|tw|hk|mo)\.cn$/i';
        $countryRegex = '/\w+\.(\w{2}|com|net)\.\w{2}$/i';
        if ($hostCount > 2 && (preg_match($cnRegex, $host) || preg_match($countryRegex, $host))) {
            $host = implode('.', array_slice($hostArr, -3, 3, true));
        } else {
            $host = implode('.', array_slice($hostArr, -2, 2, true));
        }
        return $host;
    }

    /**
     * 获取插件行为、路由配置文件
     * @return string
     */
    public static function getExtraAddonsFile()
    {
        return CONF_PATH . 'extra' . DS . 'addons.php';
    }

    /**
     * 获取bootstrap.js路径
     * @return string
     */
    public static function getBootstrapFile($name)
    {
        return ADDON_PATH . $name . DS . 'bootstrap.js';
    }

    /**
     * 获取testdata.sql路径
     * @return string
     */
    public static function getTestdataFile($name)
    {
        return ADDON_PATH . $name . DS . 'testdata.sql';
    }

    /**
     * 获取指定插件的目录
     */
    public static function getAddonDir($name)
    {
        $dir = ADDON_PATH . $name . DS;
        return $dir;
    }

    /**
     * 获取插件备份目录
     */
    public static function getAddonsBackupDir()
    {
        $dir = RUNTIME_PATH . 'addons' . DS;
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        return $dir;
    }

    /**
     * 获取插件源资源文件夹
     * @param string $name 插件名称
     * @return  string
     */
    protected static function getSourceAssetsDir($name)
    {
        return ADDON_PATH . $name . DS . 'assets' . DS;
    }

    /**
     * 获取插件目标资源文件夹
     * @param string $name 插件名称
     * @return  string
     */
    protected static function getDestAssetsDir($name)
    {
        $assetsDir = ROOT_PATH . str_replace("/", DS, "public/assets/addons/{$name}/");
        return $assetsDir;
    }

    /**
     * 获取远程服务器
     * @return  string
     */
    protected static function getServerUrl()
    {
        return config('fastadmin.api_url');
    }

    /**
     * 获取检测的全局文件夹目录
     * @return  array
     */
    protected static function getCheckDirs()
    {
        return [
            'application',
            'public'
        ];
    }

    /**
     * 获取请求对象
     * @return Client
     */
    public static function getClient()
    {
        $config = Config::get('addons.client') ?: [];
        $options = [
            'base_uri'        => self::getServerUrl(),
            'timeout'         => $config['timeout'] ?? 30,
            'connect_timeout' => $config['connect_timeout'] ?? 10,
            'verify'          => true,
            'http_errors'     => $config['http_errors'] ?? true,
            'headers'         => [
                'X-REQUESTED-WITH' => 'XMLHttpRequest',
                'Referer'          => dirname(request()->root(true)),
                'User-Agent'       => 'FastAddon',
            ]
        ];
        // [SECURITY] 应用自定义 CA / SPKI 证书固定 / 限制重定向
        $options = Security::applyTransportOptions($options);
        static $client;
        if (empty($client)) {
            $client = new Client($options);
        }
        return $client;
    }

    /**
     * 发送请求
     * @return array
     * @throws Exception
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public static function sendRequest($url, $params = [], $method = 'POST')
    {
        $json = [];
        try {
            $client = self::getClient();
            $options = strtoupper($method) == 'POST' ? ['form_params' => $params] : ['query' => $params];
            $response = $client->request($method, $url, $options);
            $body = $response->getBody();
            $content = $body->getContents();
            $json = (array)json_decode($content, true);
        } catch (TransferException $e) {
            throw new Exception(__('Network error'));
        } catch (\Exception $e) {
            throw new Exception(__('Unknown data format'));
        }
        return $json;
    }

    /**
     * 匹配配置文件中info信息
     * @param ZipFile $zip
     * @return array|false
     * @throws Exception
     */
    protected static function getInfoIni($zip)
    {
        $config = [];
        // 读取插件信息
        try {
            $info = $zip->getEntryContents('info.ini');
            $config = parse_ini_string($info);
        } catch (ZipException $e) {
            throw new Exception('Unable to extract the file');
        }
        return $config;
    }

}
