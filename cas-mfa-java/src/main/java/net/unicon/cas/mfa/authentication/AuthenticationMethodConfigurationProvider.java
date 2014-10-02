package net.unicon.cas.mfa.authentication;

/**
 * Defines where authentication methods come from, which are
 * supported and how they are loaded into the application context.
 * @author Misagh Moayyed
 */
public interface AuthenticationMethodConfigurationProvider {
    /**
     * Contains authentication method.
     *
     * @param name the name
     * @return true if the method is found
     */
    boolean containsAuthenticationMethod(String name);

    /**
     * Gets authentication method.
     *
     * @param name the name
     * @return the authentication method, or null if none is found.
     */
    AuthenticationMethod getAuthenticationMethod(String name);
}
