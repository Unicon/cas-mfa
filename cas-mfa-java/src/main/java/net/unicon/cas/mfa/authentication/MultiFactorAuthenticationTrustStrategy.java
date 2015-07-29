package net.unicon.cas.mfa.authentication;

import org.jasig.cas.authentication.Authentication;
import org.springframework.webflow.execution.RequestContext;

/**
 * @author Misagh Moayyed
 */
public interface MultiFactorAuthenticationTrustStrategy {
    /**
     * Is this authentication request trusted? can we skip MFA?
     *
     * @param authentication the authentication
     * @param context the context
     * @return the true if trusted to skip mfa.
     */
    boolean isTrusted(Authentication authentication, RequestContext context);

    /**
     * Never trust authentication.
     */
    public static class MultiFactorAuthenticationNeverTrustStrategy implements MultiFactorAuthenticationTrustStrategy {
        @Override
        public boolean isTrusted(final Authentication authentication, final RequestContext context) {
            return false;
        }
    }
}
