<?php
namespace Cloudcogs\OAuth2\Client\OpenIDConnect\Grants;

use League\OAuth2\Client\Grant\AbstractGrant;

class UmaTicket extends AbstractGrant
{
    private $grant_type = "urn:ietf:params:oauth:grant-type:uma-ticket";
    
    /**
     * {@inheritDoc}
     * @see \League\OAuth2\Client\Grant\AbstractGrant::getName()
     */
    protected function getName()
    {
        return $this->grant_type;
    }

    /**
     * {@inheritDoc}
     * @see \League\OAuth2\Client\Grant\AbstractGrant::getRequiredRequestParameters()
     */
    protected function getRequiredRequestParameters()
    {
        return [
            'grant_type',
            'audience'
        ];
    }

}

