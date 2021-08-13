<?php
namespace Cloudcogs\OAuth2\Client\OpenIDConnect;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Cloudcogs\OAuth2\Client\OpenIDConnect\Exception\TokenIntrospectionException;

abstract class AbstractOIDCProvider extends AbstractProvider
{
    const OPTION_WELL_KNOWN_URL = 'well_known_endpoint';
    const OPTION_PUBLICKEY_CACHE_PROVIDER = 'publickey_cache_provider';

    protected $OIDCDiscovery;
    
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
     */
    public function __construct(array $options, array $collaborators = [])
    {
        $this->assertRequiredOptions($options);
        
        parent::__construct($options, $collaborators);
        
        // Setup the default cache adapter if none was provided
        $cache_provider = $options[self::OPTION_PUBLICKEY_CACHE_PROVIDER];
        if (empty($cache_provider))
        {
            $cache_provider = new \Laminas\Cache\Storage\Adapter\Filesystem();
            $cache_provider->setOptions([
                'cache_dir' => dirname(__DIR__).'/../data',
                'suffix' => $this->clientId
            ]);
        }
        
        // Create and run the discovery object
        $this->OIDCDiscovery = new Discovery($this, $options[self::OPTION_WELL_KNOWN_URL], $cache_provider);
    }
    
    /**
     * Proxy to \League\OAuth2\Client\Provider\OpenIDConnect\Discovery
     * 
     * @return \League\OAuth2\Client\Provider\OpenIDConnect\Discovery
     */
    public function Discovery()
    {
        return $this->OIDCDiscovery;
    }

    /**
     * 
     * {@inheritDoc}
     * @see \League\OAuth2\Client\Provider\AbstractProvider::getResourceOwnerDetailsUrl()
     */
    public function getResourceOwnerDetailsUrl(AccessTokenInterface $token)
    {
        return $this->OIDCDiscovery->getUserInfoEndpoint();
    }

    /**
     * 
     * {@inheritDoc}
     * @see \League\OAuth2\Client\Provider\AbstractProvider::getBaseAuthorizationUrl()
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->OIDCDiscovery->getAuthorizationEndpoint();
    }

    /**
     * 
     * {@inheritDoc}
     * @see \League\OAuth2\Client\Provider\AbstractProvider::getBaseAccessTokenUrl()
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->OIDCDiscovery->getTokenEndpoint();
    }
    
    /**
     * Decode a token (either locally or remotely if introspection endpoint is available) 
     * 
     * @param string $token
     * @throws TokenIntrospectionException
     * 
     * @return \Cloudcogs\OAuth2\Client\OpenIDConnect\ParsedToken
     */
    public function introspectToken($token)
    {
        $jwt_allowed_algs = [
            'ES384','ES256', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'
        ];
        
        $resolved_algs = array_intersect($this->OIDCDiscovery->getUserInfoSigningAlgValuesSupported(), $jwt_allowed_algs);
        
        // Decode locally using cached JWK
        try {
            return new ParsedToken(json_encode(JWT::decode($token, JWK::parseKeySet($this->OIDCDiscovery->getPublicKey()), $resolved_algs)));
        } catch (\Exception $e) 
        {
            
            // Try the provider token introspection endpoint
            try {
                
                $introspectionEndpoint = $this->OIDCDiscovery->getIntrospectionEndpoint();
                
                if(!is_null($introspectionEndpoint))
                {
                    $requestBody = "client_id=".$this->clientId."&client_secret=".$this->clientSecret."&token=".$token;
                    $HttpRequest = $this->getRequestFactory()->getRequest(AbstractProvider::METHOD_POST, $introspectionEndpoint, 
                        [
                            'Content-Type'=>'application/x-www-form-urlencoded',
                            'Accept'=>'application/json'
                        ],$requestBody);
                    
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
            } catch (\Exception $e)
            {
                throw new TokenIntrospectionException($e->getMessage(), null, $e);
            }
        }
    }
    
    protected function getRequiredOptions()
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
     * @throws InvalidArgumentException
     */
    private function assertRequiredOptions(array $options)
    {
        $missing = array_diff_key(array_flip($this->getRequiredOptions()), $options);
        
        if (!empty($missing)) {
            throw new \InvalidArgumentException(
                'Required options not defined: ' . implode(', ', array_keys($missing))
                );
        }
    }
}
