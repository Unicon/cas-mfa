package net.unicon.cas.mfa.authentication;

import org.jasig.cas.authentication.principal.WebApplicationService;

import java.io.Serializable;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource;

/**
 * Holds a requested authentication method along with a target <code>WebApplicationService</code>
 * and an authentication method request source.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public final class MultiFactorAuthenticationRequestContext implements Serializable {
    private static final long serialVersionUID = -2464940656897107660L;

    /**
     * Requested authentication method.
     */
    private final String authenticationMethod;

    /**
     * Target service.
     */
    private final WebApplicationService targetService;

    /**
     * Authentication method source.
     */
    private final AuthenticationMethodSource authenticationMethodSource;

    /**
     * Ctor.
     *
     * @param authenticationMethod authenticationMethod
     * @param targetService targetService
     * @param authenticationMethodSource authenticationMethodSource
     */
    public MultiFactorAuthenticationRequestContext(final String authenticationMethod,
                                                   final WebApplicationService targetService,
                                                   final AuthenticationMethodSource authenticationMethodSource) {

        this.authenticationMethod = authenticationMethod;
        this.targetService = targetService;
        this.authenticationMethodSource = authenticationMethodSource;
    }

    public String getAuthenticationMethod() {
        return authenticationMethod;
    }

    public WebApplicationService getTargetService() {
        return targetService;
    }
    
    public AuthenticationMethodSource getAuthenticationMethodSource() {
        return authenticationMethodSource;
    }
}
