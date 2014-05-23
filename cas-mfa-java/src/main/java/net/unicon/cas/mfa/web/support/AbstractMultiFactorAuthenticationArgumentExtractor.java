package net.unicon.cas.mfa.web.support;

import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.web.support.AbstractSingleSignOutEnabledArgumentExtractor;
import org.jasig.cas.web.support.ArgumentExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Set;

/**
 * Abstract extractor containing common functionality pertaining to authentication methods verification and target service extraction
 * that subclasses delegate to.
 *
 * @author Misagh Moayyed
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public abstract class AbstractMultiFactorAuthenticationArgumentExtractor extends AbstractSingleSignOutEnabledArgumentExtractor {

    /**
     * Supported authentication methods.
     */
    private final List<String> supportedAuthenticationMethods;

    /**
     * Target argument extractors.
     */
    private final Set<ArgumentExtractor> supportedArgumentExtractors;

    /**
     * This log would be replaced by the superclass's log if CAS-1332 realized.
     */
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Create an instance of {@link net.unicon.cas.mfa.web.support.AbstractMultiFactorAuthenticationArgumentExtractor}.
     * @param authnMethods list of supported values for authentication method
     * @param supportedProtocols set of argument extractors for each protocol that are to support MFA
     */
    public AbstractMultiFactorAuthenticationArgumentExtractor(final List<String> authnMethods, final Set<ArgumentExtractor> supportedProtocols) {
        this.supportedAuthenticationMethods = authnMethods;
        this.supportedArgumentExtractors = supportedProtocols;
    }

    /**
     * Extract a target service. Delegates to wrapped argument extractors.
     * @param request http request
     * @return target service that would potentially be wrapped with an MFA supporting service
     */
    protected final WebApplicationService getTargetService(final HttpServletRequest request) {
        WebApplicationService targetService = null;
        for (final ArgumentExtractor extractor : this.supportedArgumentExtractors) {
            targetService = extractor.extractService(request);
            if (targetService != null) {
                logger.debug("[{}] intercepted the request successfully for multifactor authentication",
                        extractor);
                break;
            }
        }

        if (targetService == null) {
            logger.debug("Request is unable to identify the target application");
            return null;
        }
        return targetService;
    }

    /**
     * Verifies validity of the requested authentication method.
     *
     * @param authenticationMethod to check
     * @param targetService target service
     * @param request Http request
     */
    protected final void verifyAuthenticationMethod(final String authenticationMethod, final WebApplicationService targetService, final HttpServletRequest request) {
        if (!supportedAuthenticationMethods.contains(authenticationMethod)) {
            logger.debug("CAS is not configured to support [{}] authentication method value [{}].",
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
        }
    }

}
