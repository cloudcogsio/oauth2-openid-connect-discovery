<?php
namespace Cloudcogs\OAuth2\Client\OpenIDConnect\Exception;

class InvalidUrlException extends \Exception
{
    public function __construct ($message = null, $code = null, $previous = null) {
        $this->message = "Invalid URL [$message]";
    }
}

