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
     * Parameter name that defines the HTTP method used to send the
     * authentication response back to a service.
     */
    String CONST_PARAM_METHOD = "method";

    /**
     * Define the authentication method accepted and supported by this MFA service.
     * @return the supported method
     */
    String getAuthenticationMethod();

    /**
     * An authentication method source for this MFA service.
     * @return the source for the supported authentication method
     */
    AuthenticationMethodSource getAuthenticationMethodSource();


    /**
     * Enum type representing the type of authentication method source.
     */
    enum AuthenticationMethodSource {
        /** Sourced from registered service attribute. */
        REGISTERED_SERVICE_DEFINITION,

        /** Sourced from HTTP request param. */
        REQUEST_PARAM,

        /** Sourced from principal attribute. */
        PRINCIPAL_ATTRIBUTE
    }
}
