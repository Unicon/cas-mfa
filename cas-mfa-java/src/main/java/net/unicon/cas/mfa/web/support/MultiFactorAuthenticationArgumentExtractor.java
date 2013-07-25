package net.unicon.cas.mfa.web.support;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.web.support.AbstractSingleSignOutEnabledArgumentExtractor;
import org.springframework.util.StringUtils;

/**
 * The multifactor authentication argument extractor, responsible to
 * instruct CAS with the constructed instance of a {@link WebApplicationService}
 * that is supported based on the configured {@link #supportedAuthenticationMethods}.
 * @author Misagh Moayyed
 */
public final class MultiFactorAuthenticationArgumentExtractor extends AbstractSingleSignOutEnabledArgumentExtractor {

    /**
     * The name of the request parameter conveying the service identifier.
     */
    public static final String CONST_PARAM_SERVICE = "service";

    /**
     * Alternative name of request parameter conveying the service identifier.
     */
    public static final String CONST_PARAM_TARGET_SERVICE = "targetService";

    /**
     * Name of the request parameter conveying the ticket identifier.
     */
    public static final String CONST_PARAM_TICKET = "ticket";

    private final List<String> supportedAuthenticationMethods;

    /**
     * This log would be replaced by the superclass's log if CAS-1332 realized.
     */
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Create an instance of {@link MultiFactorAuthenticationArgumentExtractor}.
     * @param authnMethods list of supported values for authentication method
     */
    public MultiFactorAuthenticationArgumentExtractor(final List<String> authnMethods) {
        this.supportedAuthenticationMethods = authnMethods;
    }

    @Override
    protected WebApplicationService extractServiceInternal(final HttpServletRequest request) {

        logger.debug("Attempting to extract multifactor authentication parameters from the request");
        final String targetService = request.getParameter(CONST_PARAM_TARGET_SERVICE);
        final String authenticationMethod =
                request.getParameter(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD);
        final String serviceToUse =
                StringUtils.hasText(targetService) ? targetService : request.getParameter(CONST_PARAM_SERVICE);

        if (!StringUtils.hasText(serviceToUse)) {
            logger.debug("Request has no request parameter [{}]", CONST_PARAM_SERVICE);
            return null;
        }

        if (!StringUtils.hasText(authenticationMethod)) {
            logger.debug("Request has no request parameter [{}]",
                    MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD);
            return null;
        }

        if (!supportedAuthenticationMethods.contains(authenticationMethod)) {
            logger.debug("CAS is not configured to support [{}] parameter value [{}].",
                    MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD,
                    authenticationMethod);
            return null;
        }

        final String id = exciseJsessionFromUrl(serviceToUse);
        final String artifactId = request.getParameter(CONST_PARAM_TICKET);

        final MultiFactorAuthenticationSupportingWebApplicationService svc =
                new DefaultMultiFactorAuthenticationSupportingWebApplicationService(
                        id, serviceToUse, artifactId, getHttpClientIfSingleSignOutEnabled(), authenticationMethod);
        logger.debug("Created multifactor authentication request for [{}] with [{}] as [{}].",
                svc.getId(), MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD,
                svc.getAuthenticationMethod());
        return svc;
    }

    /**
     * Duplicate of AbstractWebApplicationService.cleanupUrl(), which wasn't accessible to this extractor class.
     * Excises out a jsession identifier from the service URL, if any.
     * @param url String representation of URL potentially needing cleanup
     * @return Cleaned up String representation of URL, or null
     */
    protected static String exciseJsessionFromUrl(final String url) {
        if (url == null) {
            return null;
        }

        final int jsessionPosition = url.indexOf(";jsession");

        if (jsessionPosition == -1) {
            return url;
        }

        final int questionMarkPosition = url.indexOf("?");

        if (questionMarkPosition < jsessionPosition) {
            return url.substring(0, url.indexOf(";jsession"));
        }

        return url.substring(0, jsessionPosition)
                + url.substring(questionMarkPosition);
    }
}
