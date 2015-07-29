package net.unicon.cas.mfa.authentication.loc;

import org.jasig.cas.authentication.Authentication;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Misagh Moayyed
 */
public class DefaultAuthenticationRegistry implements AuthenticationRegistry {
    private Map<Authentication, AuthenticationLocation> historyMap;

    /**
     * Instantiates a new Default authentication registry.
     */
    public DefaultAuthenticationRegistry() {
        this(new ConcurrentHashMap<Authentication, AuthenticationLocation>());
    }

    /**
     * Instantiates a new Default authentication registry.
     *
     * @param historyMap the history map
     */
    public DefaultAuthenticationRegistry(final Map<Authentication, AuthenticationLocation> historyMap) {
        this.historyMap = historyMap;
    }

    @Override
    public AuthenticationLocation locate(final Authentication authn) {
        return this.historyMap.get(authn);
    }

    @Override
    public void save(final Authentication authentication, final AuthenticationLocation location) {
        this.historyMap.put(authentication, location);
    }
}
