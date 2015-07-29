package net.unicon.cas.mfa.authentication.loc;

import org.jasig.cas.authentication.Authentication;

/**
 * @author Misagh Moayyed
 */
public interface AuthenticationRegistry {

    /**
     * Locate authentication in the registry.
     *
     * @param authn the authn
     * @return the authentication location
     */
    AuthenticationLocation locate(Authentication authn);

    /**
     * Save authentication location.
     *
     * @param authentication the authentication
     * @param location the location
     */
    void save(Authentication authentication, AuthenticationLocation location);
}
