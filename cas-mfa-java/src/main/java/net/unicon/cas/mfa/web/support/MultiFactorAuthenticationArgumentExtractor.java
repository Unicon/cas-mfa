package net.unicon.cas.mfa.web.support;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.web.support.AbstractSingleSignOutEnabledArgumentExtractor;
import org.jasig.cas.web.support.ArgumentExtractor;
import org.springframework.util.StringUtils;

/**
 * The multifactor authentication argument extractor, responsible to
 * instruct CAS with the constructed instance of a {@link WebApplicationService}
 * that is supported based on the configured {@link #supportedAuthenticationMethods}.
 * @author Misagh Moayyed
 */
public final class MultiFactorAuthenticationArgumentExtractor extends AbstractSingleSignOutEnabledArgumentExtractor {
    private final List<String> supportedAuthenticationMethods;

    private final Set<ArgumentExtractor> supportedArgumentExtractors;

    /**
     * This log would be replaced by the superclass's log if CAS-1332 realized.
     */
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Create an instance of {@link MultiFactorAuthenticationArgumentExtractor}.
     * @param authnMethods list of supported values for authentication method
     * @param supportedProtocols set of argument extractors for each protocol that are to support MFA
     */
    public MultiFactorAuthenticationArgumentExtractor(final List<String> authnMethods, final Set<ArgumentExtractor> supportedProtocols) {
        this.supportedAuthenticationMethods = authnMethods;
        this.supportedArgumentExtractors = supportedProtocols;
    }

    @Override
    protected WebApplicationService extractServiceInternal(final HttpServletRequest request) {
        logger.debug("Attempting to extract multifactor authentication parameters from the request");

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

        final String authenticationMethod =
                request.getParameter(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD);

        if (!StringUtils.hasText(authenticationMethod)) {
            logger.debug("Request has no request parameter [{}]",
                    MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD);
            return null;
        }

        if (!supportedAuthenticationMethods.contains(authenticationMethod)) {
            logger.debug("CAS is not configured to support [{}] parameter value [{}].",
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

        final MultiFactorAuthenticationSupportingWebApplicationService svc =
                new DefaultMultiFactorAuthenticationSupportingWebApplicationService(
                        targetService.getId(), targetService.getId(), targetService.getArtifactId(),
                        getHttpClientIfSingleSignOutEnabled(),
                        authenticationMethod);
        logger.debug("Created multifactor authentication request for [{}] with [{}] as [{}].",
                svc.getId(), MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD,
                svc.getAuthenticationMethod());
        return svc;
    }

}
