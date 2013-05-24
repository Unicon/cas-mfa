package net.unicon.cas.mfa.web.support;

import org.jasig.cas.authentication.principal.WebApplicationService;

/**
 * The MultiFactorAuthenticationService is an extension of the generic CAS service
 * that defines the level of assurance requires and accepted by the service.
 * @author Misagh Moayyed
 */
public interface MultiFactorAuthenticationService extends WebApplicationService {
    /**
     * Define the level of assurance accepted and supported by this MFA service.
     * @return the supported loa
     */
    String getLoa();
}
