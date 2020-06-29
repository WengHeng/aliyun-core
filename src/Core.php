<?php

namespace Everstu\Aliyun;

use Everstu\Aliyun\HttpRequest;

class Core
{
    /**
     * query params
     * @var array
     */
    protected $QueryParam = [];
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
     */
    public function __construct($config)
    {
        $this->AccessKeyId  = $config['AccessKeyId'];
        $this->AccessSecret = $config['AccessSecret'];
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
        $httpTool = new HttpRequest();
        $method   = strtolower($this->QueryMethod);
        if (in_array($method, ['post', 'get']) == false)
        {
            throw new \Exception('Method Not Allow,It\'s get|post');
        }
        $this->getSignature();//获取请求签名
        $queryUrl = ($this->security ? 'https://' : 'http://') . $this->baseApi;//生成请求URL
        $httpTool->$method($queryUrl, $this->QueryParam);

        return $httpTool;
    }

    /**
     * @param string|integer $key 请求参数的键
     * @param string $param 请求参数的值
     * @access protected
     *  绑定请求的参数
     */
    protected function setQueryParam($key, $param)
    {
        $this->QueryParam[$key] = $param;
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
     * @access protected
     *  根据参数生成请求的签名
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
}