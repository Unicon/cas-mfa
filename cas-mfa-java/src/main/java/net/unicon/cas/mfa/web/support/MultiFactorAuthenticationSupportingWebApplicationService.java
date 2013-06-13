package net.unicon.cas.mfa.web.support;

import org.jasig.cas.authentication.principal.WebApplicationService;

/**
 * The MultiFactorAuthenticationService is an extension of the generic CAS {@link WebApplicationService}
 * that defines the authentication method accepted by the service.
 * @author Misagh Moayyed
 */
public interface MultiFactorAuthenticationSupportingWebApplicationService extends WebApplicationService {
    /**
     * Define the authentication method accepted and supported by this MFA service.
     * @return the supported method
     */
    String getAuthenticationMethod();
}
