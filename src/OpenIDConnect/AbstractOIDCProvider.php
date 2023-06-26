<?php
namespace Cloudcogs\OAuth2\Client\OpenIDConnect;

use Cloudcogs\OAuth2\Client\OpenIDConnect\Exception\InvalidUrlException;
use Cloudcogs\OAuth2\Client\OpenIDConnect\Exception\WellKnownEndpointException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Cloudcogs\OAuth2\Client\OpenIDConnect\Exception\TokenIntrospectionException;

abstract class AbstractOIDCProvider extends AbstractProvider
{
    const OPTION_WELL_KNOWN_URL = 'well_known_endpoint';
    const OPTION_PUBLICKEY_CACHE_PROVIDER = 'publickey_cache_provider';

    protected Discovery $OIDCDiscovery;
    protected \stdClass $headers;

    /**
     * Compatible with league\oauth2-client 2.x
     *
     * Clients written for Identity Providers that support OpenID Connect Discovery can extend this class instead of 'League\OAuth2\Client\Provider\AbstractProvider'
     *
     * Required options are:
     *   'well_known_endpoint' - The URI of the provider's .well-known/openid-configuration service
     *   'publickey_cache_provider' - A laminas cache storage adapter Laminas\Cache\Storage\Adapter\*
     *                              - Alternatively, this key can be passed as an empty string to use the default Laminas\Cache\Storage\Adapter\Filesystem adapter
     *
     * @param array $options
     * @param array $collaborators
     * @throws InvalidUrlException
     * @throws WellKnownEndpointException
     */
    public function __construct(array $options, array $collaborators = [])
    {
        $this->assertRequiredOptions($options);
        
        parent::__construct($options, $collaborators);
        
        // Set up the default cache adapter if none was provided
        $cache_provider = $options[self::OPTION_PUBLICKEY_CACHE_PROVIDER];
        if (empty($cache_provider))
        {
            $default_dir = getcwd()."/data/oidc-discovery-cache";
            if (!is_dir($default_dir))
            {
                mkdir($default_dir,0777,true);
            }
            $cache_provider = new \Laminas\Cache\Storage\Adapter\Filesystem();
            $cache_provider->setOptions([
                'cache_dir' => $default_dir,
                'suffix' => $this->clientId
            ]);
        }
        
        // Create and run the discovery object
        $this->OIDCDiscovery = new Discovery($this, $options[self::OPTION_WELL_KNOWN_URL], $cache_provider);
    }
    
    /**
     * Proxy to \Cloudcogs\OAuth2\Client\OpenIDConnect\Discovery
     * 
     * @return Discovery
     */
    public function Discovery(): Discovery
    {
        return $this->OIDCDiscovery;
    }

    /**
     * 
     * {@inheritDoc}
     * @see \League\OAuth2\Client\Provider\AbstractProvider::getResourceOwnerDetailsUrl()
     */
    public function getResourceOwnerDetailsUrl(AccessTokenInterface $token): ?string
    {
        return $this->OIDCDiscovery->getUserInfoEndpoint();
    }

    /**
     * 
     * {@inheritDoc}
     * @see \League\OAuth2\Client\Provider\AbstractProvider::getBaseAuthorizationUrl()
     */
    public function getBaseAuthorizationUrl(): string
    {
        return $this->OIDCDiscovery->getAuthorizationEndpoint();
    }

    /**
     * 
     * {@inheritDoc}
     * @see \League\OAuth2\Client\Provider\AbstractProvider::getBaseAccessTokenUrl()
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->OIDCDiscovery->getTokenEndpoint();
    }

    /**
     * Decode a token (either locally or remotely if introspection endpoint is available)
     *
     * @param string $token
     * @param array $queryParams
     * @param bool $decode_locally
     * @return ParsedToken
     * @throws TokenIntrospectionException|\Laminas\Cache\Exception\ExceptionInterface
     */
    public function introspectToken(string $token, array $queryParams = [], bool $decode_locally = true): ParsedToken
    {
        if ($decode_locally)
        {
            // Decode locally using cached JWK
            try {
                $this->headers = new \stdClass();
                return new ParsedToken(json_encode(JWT::decode($token, JWK::parseKeySet($this->OIDCDiscovery->getPublicKey()), $this->headers)));
            } catch (\Exception $e)
            {
                // Cache is invalid, clear and then use remote
                if ($e instanceof \UnexpectedValueException)
                {
                    $this->Discovery()->clearPublicKeyCache();
                    return $this->introspectToken($token, $queryParams, false);
                }

                throw new TokenIntrospectionException($e->getMessage(), null, $e);
            }
        }
        else {
            // Try the provider token introspection endpoint
            try {
               
                $introspectionEndpoint = $this->OIDCDiscovery->getIntrospectionEndpoint();
                
                if(!is_null($introspectionEndpoint))
                {
                    $query_params = [
                        "client_id" => $this->clientId,
                        "client_secret" => $this->clientSecret,
                        "token" => $token
                    ];
                    
                    if (!empty($queryParams))
                    {
                        $query_params = array_merge($query_params, $queryParams);
                    }
                    
                    $http_query_string = http_build_query($query_params);
                    
                    $HttpRequest = $this->getRequestFactory()->getRequest(AbstractProvider::METHOD_POST, $introspectionEndpoint,
                        [
                            'Content-Type'=>'application/x-www-form-urlencoded',
                            'Accept'=>'application/json'
                        ], $http_query_string);
                    
                    $HttpResponse = $this->getResponse($HttpRequest);
                    
                    if ($HttpResponse->getStatusCode() == "200")
                    {
                        return new ParsedToken((string) $HttpResponse->getBody());
                    }
                    else
                    {
                        throw new TokenIntrospectionException($HttpResponse->getReasonPhrase(), $HttpResponse->getStatusCode());
                    }
                    
                } 
                else {
                    throw new TokenIntrospectionException("Invalid Token Introspection Endpoint");
                }
            } catch (\Exception $e)
            {
                throw new TokenIntrospectionException($e->getMessage(), null, $e);
            }
        }
    }
    
    protected function getRequiredOptions(): array
    {
        return [
            self::OPTION_WELL_KNOWN_URL,
            self::OPTION_PUBLICKEY_CACHE_PROVIDER
        ];
    }
    
    /**
     * Verifies that all required options have been passed.
     *
     * @param  array $options
     * @return void
     * @throws \InvalidArgumentException
     */
    private function assertRequiredOptions(array $options): void
    {
        $missing = array_diff_key(array_flip($this->getRequiredOptions()), $options);
        
        if (!empty($missing)) {
            throw new \InvalidArgumentException(
                'Required options not defined: ' . implode(', ', array_keys($missing))
                );
        }
    }
}
