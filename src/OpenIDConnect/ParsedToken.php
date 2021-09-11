<?php
namespace Cloudcogs\OAuth2\Client\OpenIDConnect;

/**
 * Implments RFC7519 registered claims as getters
 * Other claims can be accessed by overloading.
 * Casting to string will return the token data as a JSON string.
 */
class ParsedToken
{
    protected $data;
    
    public function __construct(string $json)
    {
        $this->data = json_decode($json);
    }
    
    /**
     * "iss" (Issuer) Claim
     *
     * The "iss" (issuer) claim identifies the principal that issued the
     * JWT.  The processing of this claim is generally application specific.
     * The "iss" value is a case-sensitive string containing a StringOrURI value.
     *
     * Use of this claim is OPTIONAL.
     
     * @return string | null
     */
    public function getIssuer()
    {
        return $this->iss;
    }
    
    /**
     * "sub" (Subject) Claim
     *
     * The "sub" (subject) claim identifies the principal that is the
     * subject of the JWT.  The claims in a JWT are normally statements
     * about the subject.  The subject value MUST either be scoped to be
     * locally unique in the context of the issuer or be globally unique.
     * The processing of this claim is generally application specific.
     * The"sub" value is a case-sensitive string containing a StringOrURI value.
     *
     * Use of this claim is OPTIONAL.
     *
     * @return string | null
     */
    public function getSubject()
    {
        return $this->sub;
    }
    
    /**
     * "aud" (Audience) Claim
     *
     * The "aud" (audience) claim identifies the recipients that the JWT is
     * intended for.  Each principal intended to process the JWT MUST
     * identify itself with a value in the audience claim.  If the principal
     * processing the claim does not identify itself with a value in the
     * "aud" claim when this claim is present, then the JWT MUST be rejected.
     * In the general case, the "aud" value is an array of case-sensitive strings,
     * each containing a StringOrURI value.  In the special case when the JWT has
     * one audience, the "aud" value MAY be a single case-sensitive string containing a StringOrURI value.
     * The interpretation of audience values is generally application specific.
     *
     * Use of this claim is OPTIONAL.
     *
     * @return mixed string | array | null
     */
    public function getAudience()
    {
        return $this->aud;
    }
    
    /**
     * "exp" (Expiration Time) Claim
     *
     * The "exp" (expiration time) claim identifies the expiration time on
     * or after which the JWT MUST NOT be accepted for processing.
     * The processing of the "exp" claim requires that the current date/time
     * MUST be before the expiration date/time listed in the "exp" claim.
     * Implementers MAY provide for some small leeway, usually no more than a few minutes,
     * to account for clock skew.  Its value MUST be a number containing a NumericDate value.
     *
     * Use of this claim is OPTIONAL.
     *
     * Takes an optional format string which will return the formatted exp value using date($date_format,exp);
     *
     * @return int | null
     */
    public function getExpirationTime(string $date_format = null)
    {
        if ($date_format && $this->exp) return date($date_format, intval($this->exp));
        
        return $this->exp;
    }
    
    /**
     * "nbf" (Not Before) Claim
     *
     * The "nbf" (not before) claim identifies the time before which the JWT
     * MUST NOT be accepted for processing.  The processing of the "nbf" claim
     * requires that the current date/time MUST be after or equal to the not-before
     * date/time listed in the "nbf" claim.  Implementers MAY provide for some small leeway,
     * usually no more than a few minutes, to account for clock skew.
     * Its value MUST be a number containing a NumericDate value.
     *
     * Use of this claim is OPTIONAL.
     *
     * Takes an optional format string which will return the formatted nbf value using date($date_format,nbf);
     *
     * @return int | null
     */
    public function getNotBefore(string $date_format = null)
    {
        if ($date_format && $this->nbf) return date($date_format, intval($this->nbf));
        
        return $this->nbf;
    }
    
    /**
     * "iat" (Issued At) Claim
     *
     * The "iat" (issued at) claim identifies the time at which the JWT was issued.
     * This claim can be used to determine the age of the JWT.  Its value MUST be a
     * number containing a NumericDate value.
     *
     * Use of this claim is OPTIONAL.
     *
     * Takes an optional format string which will return the formatted iat value using date($date_format,iat);
     *
     * @return int | null
     */
    public function getIssuedAt(string $date_format = null)
    {
        if ($date_format && $this->iat) return date($date_format, intval($this->iat));
        
        return $this->iat;
    }
    
    /**
     * "jti" (JWT ID) Claim
     *
     * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     * The identifier value MUST be assigned in a manner that ensures that
     * there is a negligible probability that the same value will be accidentally
     * assigned to a different data object; if the application uses multiple issuers,
     * collisions MUST be prevented among values produced by different issuers as well.
     * The "jti" claim can be used to prevent the JWT from being replayed.
     * The "jti" value is a case-sensitive string.
     *
     * Use of this claim is OPTIONAL.
     *
     * @return string | null
     */
    public function getJwtId()
    {
        return $this->jti;
    }
    
    /**
     * Determine if the token has expired
     *
     * @return boolean
     */
    public function isExpired()
    {
        return ($this->getExpirationTime() < time());
    }
    
    /**
     * Determine if the token is valid based on the "Not Before" and "Expiration Time" claims
     *
     * @return boolean
     */
    public function isValid()
    {
        if (time() >= $this->getNotBefore() && !$this->isExpired()) return true;
        
        return false;
    }
    
    /**
     * Return an array of available claims for the token
     *
     * @return array
     */
    public function getAvailableClaims()
    {
        return array_keys((array) $this->data);
    }
    
    /**
     * Return the token data as an array
     *
     * @return array
     */
    public function toArray()
    {
        return (array) $this->data;
    }
    
    public function __get($property)
    {
        return (property_exists($this->data, $property)) ? $this->data->$property : null;
    }
    
    public function __toString()
    {
        return json_encode($this->data);
    }
}
