# OpenID Connect Discovery support for League - OAuth 2.0 Client

This library extends the [League OAuth2 Client](https://github.com/thephpleague/oauth2-client) library to provide OpenID Connect Discovery support for providers that expose a ```.well-known``` configuration endpoint.

 
## Installation
To install in an existing (or new) Oauth2 Client Provider library:
1. Use composer:

```
composer require cloudcogsio/oauth2-openid-connect-discovery
```

2. Change the client to extend ```\Cloudcogs\OAuth2\Client\OpenIDConnect\AbstractOIDCProvider``` instead of ```\League\OAuth2\Client\Provider\AbstractProvider```

3. Remove the following methods
> ~~getResourceOwnerDetailsUrl~~
> ~~getBaseAuthorizationUrl~~
> ~~getBaseAccessTokenUrl~~

##### Existing OAuth2 Client
```php

class MyCustomClient extends \League\OAuth2\Client\Provider\AbstractProvider
{
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        ...
    }

    public function getBaseAuthorizationUrl()
    {
        ...
    }

    public function getBaseAccessTokenUrl(array $params)
    {
        ...
    }
}

```

##### Updated OAuth2 Client with OpenID Connect Discovery Support
```php

class MyCustomClient extends \Cloudcogs\OAuth2\Client\OpenIDConnect\AbstractOIDCProvider
{
    ...
}

```
The existing client can now make use of the OIDC mechanisms implemented by this library.

See https://oauth2-client.thephpleague.com/providers/implementing for more information on implementing a new Client Provider.

## Usage
Usage is the same as The League's OAuth client.
Configuration options changes are required.

##### URL options can be removed
>~~'urlAuthorize'~~ 
>~~'urlAccessToken'~~ 
>~~'urlResourceOwnerDetails'~~ 
 
 
 ##### Existing configuration
 ```php

$provider = new MyCustomClient([
    'clientId'                => 'XXXXXX',    // The client ID assigned to you by the provider
    'clientSecret'            => 'XXXXXX',    // The client password assigned to you by the provider
    'redirectUri'             => 'https://my.example.com/your-redirect-url/',
    'urlAuthorize'            => 'https://service.example.com/authorize',
    'urlAccessToken'          => 'https://service.example.com/token',
    'urlResourceOwnerDetails' => 'https://service.example.com/resource'
]);

```


 ##### New configuration
```php

$provider = new MyCustomClient([
    'clientId'                => 'XXXXXX',    // The client ID assigned to you by the provider
    'clientSecret'            => 'XXXXXX',    // The client password assigned to you by the provider
    'redirectUri'             => 'https://my.example.com/your-redirect-url/',
    'well_known_endpoint'     => 'https://identity.provider.com/.well-known/openid-configuration',
    'publickey_cache_provider'=> '',
]);

```

 - **well_known_endpoint** - The URL of the ```.well-known/openid-configuration``` endpoint of the IDP.
 - **publickey_cache_provider** - An empty string
OR
An instance of a ```\Laminas\Cache\Storage\Adapter\*``` storage adapter. See https://github.com/laminas/laminas-cache




## Additional Notes and Usage

Your client provider instance will now have added functionality such as token introspection (if supported by your IDP) and the ability to obtain further configuration details from the provider.

Configuration data is accessed by proxying to the ```Discovery``` object from the client provider.
```php

// Get the discovered configurations from the provider instance
$discovered = $provider->Discovery();

// Access standard OpenID Connect configuration via supported methods
$issuer = $discovered->getIssuer();
$supported_grants = $discovered->getGrantTypesSupported();
$authorization_endpoint = $discovered->getAuthorizationEndpoint();

// Or overloading for provider specific configuration
$custom_config = $discovered->custom_config;

// Cast to string to obtain the raw JSON discovery response
// All available properties for overloading can be seen in the JSON object.
$json_string = (string) $discovered;

```

### IDP Public Key(s)
During endpoint discovery, the IDP public key(s) are retrieved and cached locally. This is needed to decode the access token (if required).

#### Caching of Public Keys
Caching of JWKs are handled by an instance of a ```\Laminas\Cache\Storage\Adapter\*``` storage adapter. If none is provided, ```\Laminas\Cache\Storage\Adapter\FileSystem``` is used.

You can provide your own instance of a ```\Laminas\Cache\Storage\Adapter\*``` to handle storage of the public keys.
##### Example
```php

$storageAdapter = new \Laminas\Cache\Storage\Adapter\MongoDB($mdbOptions);

$provider = new MyCustomClient([
    'clientId'                => 'XXXXXX',    // The client ID assigned to you by the provider
    'clientSecret'            => 'XXXXXX',    // The client password assigned to you by the provider
    'redirectUri'             => 'https://my.example.com/your-redirect-url/',
    'well_known_endpoint'     => 'https://identity.provider.com/.well-known/openid-configuration',
    'publickey_cache_provider'=> $storageAdapter,
]);

```


### Token Introspection
The AccessToken issued by the IDP can be decoded locally to obtain additional information.
```php

// Decode the access token
$access_token = $AccessToken->getToken();
$data = $provider->introspectToken($access_token);

```

#### Token Introspection via the IDP (optional)
All tokens issued by the IDP (accessToken, refreshToken etc.) can be introspected using the token introspection endpoint if one is made available by the IDP.


```php

// Decode the refresh token
$refresh_token = $AccessToken->getRefreshToken();
$data = $provider->introspectToken($refresh_token);

```


## License
The MIT License (MIT). Please see  [License File](https://github.com/cloudcogsio/oauth2-openid-connect-discovery/blob/master/LICENSE.md)  for more information.
