package net.unicon.cas.mfa.web.support;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;

import org.jasig.cas.authentication.principal.AbstractWebApplicationService;
import org.jasig.cas.authentication.principal.Response;
import org.jasig.cas.authentication.principal.SimpleWebApplicationServiceImpl;
import org.jasig.cas.util.HttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

/**
 * The MultiFactorAuthenticationService is an extension of the generic CAS service
 * that delegates calls to {@link SimpleWebApplicationServiceImpl}. The only difference
 * is that it is only is activated when the request parameter {@link #CONST_PARAM_AUTHN_METHOD} is
 * present and its value is supported by the corresponding argument extractor.
 * <p>NOTE: The delegation is necessary because the {@link SimpleWebApplicationServiceImpl}
 * itself is marked as final. Future versions of CAS might make the class more available.
 * Cf CAS server RFE https://github.com/Jasig/cas/issues/284 .
 * @author Misagh Moayyed
 */
public final class DefaultMultiFactorAuthenticationSupportingWebApplicationService extends AbstractWebApplicationService implements
        MultiFactorAuthenticationSupportingWebApplicationService {

    /** The logger instance. **/
    protected static final Logger LOGGER = LoggerFactory.getLogger(DefaultMultiFactorAuthenticationSupportingWebApplicationService.class);

    private static final long serialVersionUID = 7537062414761087535L;

    private static final String CONST_PARAM_SERVICE = "service";

    private static final String CONST_PARAM_TARGET_SERVICE = "targetService";

    private static final String CONST_PARAM_TICKET = "ticket";

    private final SimpleWebApplicationServiceImpl wrapperService;

    private final String authenticationMethod;

    /**
     * Create an instance of {@link DefaultMultiFactorAuthenticationSupportingWebApplicationService}.
     * Expects the request parameter {@link #CONST_PARAM_AUTHN_METHOD} is
     * present and its value is supported by the corresponding argument extractor.
     * @param id the service id
     * @param originalUrl the service url from the request, noted by {@link #CONST_PARAM_SERVICE} or {@link #CONST_PARAM_TARGET_SERVICE}
     * @param artifactId the artifact id from the request, noted by {@link #CONST_PARAM_TICKET}
     * @param httpClient http client to process requests
     * @param authnMethod the authentication method parameter defined for this mfa service
     */
    protected DefaultMultiFactorAuthenticationSupportingWebApplicationService(final String id, final String originalUrl,
            final String artifactId, final HttpClient httpClient, @NotNull final String authnMethod) {
        super(id, originalUrl, artifactId, httpClient);
        this.wrapperService = new SimpleWebApplicationServiceImpl(id, httpClient);
        this.authenticationMethod = authnMethod;
    }

    @Override
    public Response getResponse(final String ticketId) {
        return wrapperService.getResponse(ticketId);
    }

    public String getAuthenticationMethod() {
        return this.authenticationMethod;
    }

    /**
     * Create an instance of {@link DefaultMultiFactorAuthenticationSupportingWebApplicationService} if loa
     * parameter is defined and supported.
     * @param request the http request
     * @param httpClient the http client
     * @param supportedLevelsOfAuthentication levels of mfa authentication supported by this service
     * @return An instance of {@link DefaultMultiFactorAuthenticationSupportingWebApplicationService}
     */
    public static MultiFactorAuthenticationSupportingWebApplicationService createServiceFrom(final HttpServletRequest request,
            final HttpClient httpClient, final List<String> supportedLevelsOfAuthentication) {
        LOGGER.debug("Attempting to extract multifactor authentication parameters from the request");
        final String targetService = request.getParameter(CONST_PARAM_TARGET_SERVICE);
        final String authenticationMethod = request.getParameter(CONST_PARAM_AUTHN_METHOD);
        final String serviceToUse = StringUtils.hasText(targetService) ? targetService : request.getParameter(CONST_PARAM_SERVICE);

        if (!StringUtils.hasText(serviceToUse)) {
            LOGGER.debug("Request has no request parameter [{}]", CONST_PARAM_SERVICE);
            return null;
        }

        if (!StringUtils.hasText(authenticationMethod)) {
            LOGGER.debug("Request has no request parameter [{}]", CONST_PARAM_AUTHN_METHOD);
            return null;
        }

        if (!supportedLevelsOfAuthentication.contains(authenticationMethod)) {
            LOGGER.debug("Multifactor authentication service does not support [{}] parameter value [{}].",
                    CONST_PARAM_AUTHN_METHOD, authenticationMethod);
            return null;
        }

        final String id = cleanupUrl(serviceToUse);
        final String artifactId = request.getParameter(CONST_PARAM_TICKET);

        final MultiFactorAuthenticationSupportingWebApplicationService svc =
                new DefaultMultiFactorAuthenticationSupportingWebApplicationService(
                id, serviceToUse, artifactId, httpClient, authenticationMethod);
        LOGGER.debug("Created multifactor authentication request for [{}] with [{}] as [{}].",
                svc.getId(), CONST_PARAM_AUTHN_METHOD, svc.getAuthenticationMethod());
        return svc;
    }
}
