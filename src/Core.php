<?php

namespace everstu\aliyun;


class Core
{
    /**
     * query params
     * @var array
     */
    protected $QueryParam = [];
    /**
     * Last time query params
     * @var array
     */
    protected $preQueryParam = [];
    /**
     * check params arr
     * @var array
     */
    protected $checkParamArr = [];
    /**
     * query method
     * @var string
     */
    public $QueryMethod = 'POST';
    /**
     * aliyun accesskeyid
     * @var mixed|string
     */
    public $AccessKeyId = '';
    /**
     * aliyun accesssecret
     * @var mixed|string
     */
    public $AccessSecret = '';
    /**
     * aliyun api service url eg: dysmsapi.aliyuncs.com
     * @var
     */
    public $baseApi = '';
    /**
     * is request https
     * @var
     */
    public $security = false;

    /**
     * Core constructor.
     * @param array $config like this ['AccessKeyId'=>'阿里云AccessKeyId','AccessSecret'=>'阿里云AccessSecret']
     * @throws \Exception
     */
    public function __construct($config)
    {
        $require_config = ['AccessKeyId', 'AccessSecret'];//必要配置项
        foreach ($require_config as $value)
        {
            if (array_key_exists($value, $config) == false)
            {
                throw new \Exception('必选配置项[' . $value . ']未传入');
            }

            if (empty($config[$value]) == true)
            {
                throw new \Exception('必选配置项[' . $value . ']为空');
            }
        }
        $this->AccessKeyId  = $config['AccessKeyId'];
        $this->AccessSecret = $config['AccessSecret'];
        $this->init();
    }

    /**
     * 初始化接口公共参数
     */
    public function init()
    {
        $this->preQueryParam = $this->QueryParam;//记录上次请求参数
        $this->QueryParam    = [];//清除上次请求参数
        $this->setQueryParam('SignatureMethod', 'HMAC-SHA1');
        $this->setQueryParam('SignatureVersion', '1.0');
        $this->setQueryParam('SignatureNonce', uniqid(mt_rand(0, 0xffff), true));
        $this->setQueryParam('AccessKeyId', $this->AccessKeyId);
        $this->setQueryParam('Timestamp', gmdate('Y-m-d\TH:i:s\Z'));
        $this->setQueryParam('Format', 'json');
    }

    /**
     * @return HttpRequest
     * @throws \Exception
     */
    public function exec()
    {
        $this->checkRequestParam();//检验参数是否正确
        $httpTool = new HttpRequest();
        $method   = strtolower($this->QueryMethod);
        if (in_array($method, ['post', 'get']) == false)//判断是否在允许请求方法内
        {
            throw new \Exception('Method Not Allow,It\'s get|post');
        }
        $this->getSignature();//获取请求签名
        $queryUrl = ($this->security ? 'https://' : 'http://') . $this->baseApi;//生成请求URL
        $httpTool->$method($queryUrl, $this->QueryParam);

        $this->init();//请求完毕自动初始化请求参数

        return $httpTool;
    }

    /**
     *  绑定请求的参数 可以设置可选请求参数 可以链式调用
     * @param string|integer $key 请求参数的键
     * @param string $param 请求参数的值
     * @return  $this
     * @access public
     */
    public function setQueryParam($key, $param)
    {
        $this->QueryParam[$key] = $param;
        $this->checkParamArr[]  = $key;

        return $this;
    }

    /**
     * @access protected
     *  根据参数生成请求的签名
     */
    protected function getSignature()
    {
        $QueryParam = $this->QueryParam;
        ksort($QueryParam);
        $canonicalQueryString = '';
        foreach ($QueryParam as $key => $value)
        {
            $canonicalQueryString .= '&' . $this->percentEncode($key) . '=' . $this->percentEncode($value);
        }
        $stringToSign = $this->QueryMethod . '&%2F&' . $this->percentEncode(substr($canonicalQueryString, 1));
        $this->buildSignature($stringToSign, $this->AccessSecret . "&");
    }

    /**
     * 替换特殊字符
     * @param string
     * @access protected
     */
    protected function percentEncode($str)
    {
        $res = urlencode($str);
        $res = preg_replace('/\+/', '%20', $res);
        $res = preg_replace('/\*/', '%2A', $res);
        $res = preg_replace('/%7E/', '~', $res);

        return $res;
    }

    /**
     * 根据参数生成请求的签名
     * @access protected
     * @param string $source
     * @param string $accessSecret
     */
    protected function buildSignature($source, $accessSecret)
    {
        $this->setQueryParam('Signature', base64_encode(hash_hmac('sha1', $source, $accessSecret, true)));
    }

    /**
     * 设置校验参数数组
     * @param $checkParamArr
     * @return $this
     */
    protected function setCheckParamArr($checkParamArr)
    {
        foreach ($checkParamArr as $value)
        {
            $this->checkParamArr[] = $value;
        }

        return $this;
    }

    /**
     * 检查请求参数是否传入或是否为空
     * @throws \Exception
     */
    protected function checkRequestParam()
    {
        $checkArr = array_unique($this->checkParamArr);
        foreach ($checkArr as $value)
        {
            if (isset($this->QueryParam[$value]) == false)
            {
                throw new \Exception('请求参数[' . $value . ']未设置');
            }

            if (empty($this->QueryParam[$value]) == true)
            {
                throw new \Exception('请求参数[' . $value . ']为空');
            }
        }
    }

    /**
     * 设置是否开启HTTPS请求接口
     * @param bool $security true 开启 false 不开启 默认true 初始值false
     */
    protected function setIsHttps($security = true)
    {
        $this->security = $security;
    }
}