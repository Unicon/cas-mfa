package net.unicon.cas.mfa.web.support;

import org.jasig.cas.authentication.principal.WebApplicationService;

/**
 * The MultiFactorAuthenticationService is an extension of the generic CAS {@link WebApplicationService}
 * that defines the authentication method accepted by the service.
 * @author Misagh Moayyed
 */
public interface MultiFactorAuthenticationSupportingWebApplicationService extends WebApplicationService {
    /** Parameter name that defined the method of authentication. **/
    String CONST_PARAM_AUTHN_METHOD = "authn_method";

    /**
     * Define the authentication method accepted and supported by this MFA service.
     * @return the supported method
     */
    String getAuthenticationMethod();
}
