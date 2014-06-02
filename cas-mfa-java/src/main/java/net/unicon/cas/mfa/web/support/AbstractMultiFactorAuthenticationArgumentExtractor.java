package net.unicon.cas.mfa.web.support;

import org.jasig.cas.authentication.principal.WebApplicationService;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.*;

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
public abstract class AbstractMultiFactorAuthenticationArgumentExtractor implements ArgumentExtractor {

    /**
     * Supported authentication methods.
     */
    private final List<String> supportedAuthenticationMethods;

    /**
     * Target argument extractors.
     */
    private final Set<ArgumentExtractor> supportedArgumentExtractors;

    /**
     * Factory for mfa services.
     */
    private final MfaWebApplicationServiceFactory mfaWebApplicationServiceFactory;

    /**
     * This log would be replaced by the superclass's log if CAS-1332 realized.
     */
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Create an instance of {@link net.unicon.cas.mfa.web.support.AbstractMultiFactorAuthenticationArgumentExtractor}.
     *
     * @param authnMethods list of supported values for authentication method
     * @param supportedProtocols set of argument extractors for each protocol that are to support MFA
     * @param mfaWebApplicationServiceFactory a factory for the mfa services that this extractor is responsible for
     */
    public AbstractMultiFactorAuthenticationArgumentExtractor(final List<String> authnMethods,
                                                              final Set<ArgumentExtractor> supportedProtocols,
                                                              final MfaWebApplicationServiceFactory mfaWebApplicationServiceFactory) {
        this.supportedAuthenticationMethods = authnMethods;
        this.supportedArgumentExtractors = supportedProtocols;
        this.mfaWebApplicationServiceFactory = mfaWebApplicationServiceFactory;
    }

    @Override
    public final WebApplicationService extractService(final HttpServletRequest request) {
        final WebApplicationService targetService = getTargetService(request);
        if (targetService == null) {
            return null;
        }
        final String authenticationMethod = getAuthenticationMethod(request, targetService);
        if (authenticationMethod == null) {
            return null;
        }
        verifyAuthenticationMethod(authenticationMethod, targetService, request);

        final MultiFactorAuthenticationSupportingWebApplicationService mfaService =
                this.mfaWebApplicationServiceFactory.create(targetService.getId(), targetService.getId(), targetService.getArtifactId(),
                        authenticationMethod, getAuthenticationMethodSource());

        logger.debug("Created multifactor authentication service instance for [{}] with [{}] as [{}] and authentication method definition source [{}].",
                mfaService.getId(), CONST_PARAM_AUTHN_METHOD,
                mfaService.getAuthenticationMethod(),
                mfaService.getAuthenticationMethodSource());

        return mfaService;
    }

    /**
     * Extract a target service. Delegates to wrapped argument extractors.
     *
     * @param request http request
     *
     * @return target service that would potentially be wrapped with an MFA supporting service
     */
    private WebApplicationService getTargetService(final HttpServletRequest request) {
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
    private void verifyAuthenticationMethod(final String authenticationMethod, final WebApplicationService targetService, final HttpServletRequest request) {
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

    /**
     * Delegates to subclasses to resolve requested authentication method.
     *
     * @param request http request
     * @param targetService target service
     *
     * @return authentication method or null if not resolved
     */
    protected abstract String getAuthenticationMethod(HttpServletRequest request, WebApplicationService targetService);

    /**
     * Delegates to subclasses to resolve target authentication method source.
     *
     * @return target authentication method source.
     */
    protected abstract AuthenticationMethodSource getAuthenticationMethodSource();

}
