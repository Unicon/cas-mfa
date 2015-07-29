package net.unicon.cas.mfa.authentication.loc;

import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationTrustStrategy;
import org.jasig.cas.authentication.Authentication;
import org.springframework.webflow.execution.RequestContext;

/**
 * @author Misagh Moayyed
 */
public class LocationBasedMultiFactorAuthenticationTrustStrategy implements MultiFactorAuthenticationTrustStrategy {
    private final AuthenticationRegistry registry;
    private final AuthenticationLocationResolver locationResolver;

    /**
     * Instantiates a new Location based multi factor authentication trust strategy.
     *
     * @param registry the registry
     * @param locationResolver the location resolver
     */
    public LocationBasedMultiFactorAuthenticationTrustStrategy(final AuthenticationRegistry registry,
                                                               final AuthenticationLocationResolver locationResolver) {
        this.registry = registry;
        this.locationResolver = locationResolver;
    }

    @Override
    public boolean isTrusted(final Authentication authentication, final RequestContext context) {
        final AuthenticationLocation existingAuthnLocation = this.registry.locate(authentication);
        final AuthenticationLocation currentAuthnLocation = this.locationResolver.resolve(context);
        if (existingAuthnLocation == null) {
            this.registry.save(authentication, currentAuthnLocation);
            return false;
        }
        return existingAuthnLocation.equals(currentAuthnLocation);
    }
}
