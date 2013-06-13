package net.unicon.cas.mfa.web.support;

import org.jasig.cas.authentication.principal.WebApplicationService;

/**
 * The MultiFactorAuthenticationService is an extension of the generic CAS {@link WebApplicationService}
 * that defines the level of assurance required and accepted by the service.
 * @author Misagh Moayyed
 */
public interface MultiFactorAuthenticationSupportingWebApplicationService extends WebApplicationService {
    /**
     * Define the level of assurance accepted and supported by this MFA service.
     * @return the supported loa
     */
    String getLoa();
}
