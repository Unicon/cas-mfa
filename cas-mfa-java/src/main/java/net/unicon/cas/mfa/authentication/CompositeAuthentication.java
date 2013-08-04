package net.unicon.cas.mfa.authentication;

import java.util.Collection;

import org.jasig.cas.authentication.Authentication;

/**
 * A composite authentication that specifically is able to collect
 * authentication methods fulfilled in the chain.
 * @author Misagh Moayyed
 */
public interface CompositeAuthentication extends Authentication {

    /**
     * Retrieves the collection of authentication methods available in the list
     * of authentication attributes.
     * @return collection of authentication methods
     */
    Collection<Object> getSatisfiedAuthenticationMethods();
}
