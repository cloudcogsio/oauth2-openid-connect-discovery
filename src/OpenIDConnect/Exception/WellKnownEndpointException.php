<?php
namespace Cloudcogs\OAuth2\Client\OpenIDConnect\Exception;

class WellKnownEndpointException extends \Exception
{
    public function __construct($message = null, $code = null, $previous = null)
    {
        $this->message = "OpenID Connect Discovery Exception [$message]";
        $this->code = $code;
    }
}
