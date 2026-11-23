<?php

namespace think\addons;

use think\Exception;

/**
 * 插件异常处理类
 * @package think\addons
 */
class AddonException extends Exception
{

    /**
     * 附加数据
     * @var mixed
     */
    public $data = '';

    public function __construct($message, $code = 0, $data = '')
    {
        $this->message  = $message;
        $this->code     = $code;
        $this->data     = $data;
    }

}
