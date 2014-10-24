package net.unicon.cas.mfa.web.support;

import net.unicon.cas.mfa.authentication.AuthenticationMethodConfigurationProvider;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;

/**
 * Default implementation of {@link net.unicon.cas.mfa.web.support.AuthenticationMethodVerifier}.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public final class DefaultAuthenticationMethodVerifier implements AuthenticationMethodVerifier {
    /**
     * The logger.
     */
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Supported authentication methods.
     */
    private final AuthenticationMethodConfigurationProvider supportedAuthenticationMethodsConfig;

    /**
     * Ctor.
     *
     * @param authenticationMethodConfiguration list of supported authentication methods
     */
    public DefaultAuthenticationMethodVerifier(
        final AuthenticationMethodConfigurationProvider authenticationMethodConfiguration) {
        this.supportedAuthenticationMethodsConfig = authenticationMethodConfiguration;
    }

    @Override
    public boolean verifyAuthenticationMethod(final String authenticationMethod,
                                           final WebApplicationService targetService,
                                           final HttpServletRequest request) {

        if (!supportedAuthenticationMethodsConfig.containsAuthenticationMethod(authenticationMethod)) {
            logger.debug("CAS is not configured to support [{}] authentication method value [{}]."
                         + "The configuration of supported authentication methods is likely missing this method.",
                    MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD,
                    authenticationMethod);
            /**
             * Argument extractors are still going to be invoked, if the flow
             * decides to move the user experience to an error-view JSP. As such,
             * and since we are unable to touch request parameters removing the invalid
             * authn_method before that navigation takes place, there's a chance that an infinite
             * redirect loop might occur. The compromise here to is to "remember" that the exception
             * was handled once via a request attribute.
             */
            if (request.getAttribute(UnrecognizedAuthenticationMethodException.class.getName()) == null) {
                request.setAttribute(UnrecognizedAuthenticationMethodException.class.getName(), Boolean.TRUE.toString());
                throw new UnrecognizedAuthenticationMethodException(authenticationMethod, targetService.getId());
            }
            return false;
        }
        return true;
    }

}
