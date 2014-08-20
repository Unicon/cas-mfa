package net.unicon.cas.mfa.web.support;

import org.jasig.cas.authentication.principal.WebApplicationService;

import javax.servlet.http.HttpServletRequest;

/**
 * Strategy interface for verifying requested mfa authentication methods.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public interface AuthenticationMethodVerifier {

    /**
     * Verify requested mfa authentication method.
     *
     * @param authenticationMethod requested authentication method
     * @param targetService targetService
     * @param request Http request
     * @return true if the authn method is supported and verified
     * @throws UnrecognizedAuthenticationMethodException if the passed in authentication method does not pass the verification
     */
    boolean verifyAuthenticationMethod(String authenticationMethod, WebApplicationService targetService, HttpServletRequest request)
            throws UnrecognizedAuthenticationMethodException;
}
