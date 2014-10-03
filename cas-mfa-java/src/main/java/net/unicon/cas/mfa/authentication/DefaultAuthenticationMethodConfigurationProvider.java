package net.unicon.cas.mfa.authentication;

import java.util.Map;

/**
 * @author Misagh Moayyed
 */
public class DefaultAuthenticationMethodConfigurationProvider implements AuthenticationMethodConfigurationProvider {
    private final Map<String, Integer> authenticationMethodsMap;

    /**
     * Instantiates a new Default authentication method configuration provider.
     *
     * @param authenticationMethodsMap the authentication methods map
     */
    public DefaultAuthenticationMethodConfigurationProvider(final Map<String, Integer> authenticationMethodsMap) {
        this.authenticationMethodsMap = authenticationMethodsMap;
    }

    @Override
    public boolean containsAuthenticationMethod(final String name) {
        return getAuthenticationMethod(name) != null;
    }

    @Override
    public AuthenticationMethod getAuthenticationMethod(final String name) {
        if (this.authenticationMethodsMap.containsKey(name)) {
            final Integer rank = this.authenticationMethodsMap.get(name);
            return new AuthenticationMethod(name, rank);
        }
        return null;
    }
}
