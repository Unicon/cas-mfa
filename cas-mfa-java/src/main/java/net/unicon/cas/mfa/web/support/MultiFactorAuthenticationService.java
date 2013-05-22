package net.unicon.cas.mfa.web.support;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

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
 * is that it is only is activated when the request parameter {@link #CONST_PARAM_LOA} is
 * present and its value is supported by the corresponding argument extractor.
 * TODO The delegation is necessary because the {@link SimpleWebApplicationServiceImpl}
 * itself is marked as final. Future versions of CAS might make the class more available.
 * @author Misagh Moayyed
 */
class MultiFactorAuthenticationService extends AbstractWebApplicationService {

    /** The logger instance. **/
    protected static final Logger LOGGER = LoggerFactory.getLogger(MultiFactorAuthenticationService.class);

    private static final long serialVersionUID = 7537062414761087535L;

    private static final String CONST_PARAM_SERVICE = "service";

    private static final String CONST_PARAM_TARGET_SERVICE = "targetService";

    private static final String CONST_PARAM_TICKET = "ticket";

    private static final String CONST_PARAM_LOA = "loa";

    private final SimpleWebApplicationServiceImpl wrapperService;

    private final String loa;

    /**
     * Create an instance of {@link MultiFactorAuthenticationService}.
     * Expects the request parameter {@link #CONST_PARAM_LOA} is
     * present and its value is supported by the corresponding argument extractor.
     * @param id the service id
     * @param originalUrl the service url from the request, noted by {@link #CONST_PARAM_SERVICE} or {@link #CONST_PARAM_TARGET_SERVICE}
     * @param artifactId the artifact id from the request, noted by {@link #CONST_PARAM_TICKET}
     * @param httpClient http client to process requests
     */
    protected MultiFactorAuthenticationService(final String id, final String originalUrl,
            final String artifactId, final HttpClient httpClient, final String loa) {
        super(id, originalUrl, artifactId, httpClient);
        this.wrapperService = new SimpleWebApplicationServiceImpl(id, httpClient);
        this.loa = loa;
    }

    @Override
    public final Response getResponse(final String ticketId) {
        return wrapperService.getResponse(ticketId);
    }

    public final String getLOA() {
        return this.loa;
    }
    /**
     * Create an instance of {@link MultiFactorAuthenticationService} if loa
     * parameter is defined and supported.
     * @param request the http request
     * @param httpClient the http client
     * @param supportedLevelsOfAuthentication levels of mfa authentication supported by this service
     * @return An instance of {@link MultiFactorAuthenticationService}
     */
    public static MultiFactorAuthenticationService createServiceFrom(final HttpServletRequest request,
            final HttpClient httpClient, final List<String> supportedLevelsOfAuthentication) {
        LOGGER.debug("Attempting to extract multifactor authentication parameters from the request");
        final String targetService = request.getParameter(CONST_PARAM_TARGET_SERVICE);
        final String loa = request.getParameter(CONST_PARAM_LOA);
        final String serviceToUse = StringUtils.hasText(targetService) ? targetService : request.getParameter(CONST_PARAM_SERVICE);

        if (!StringUtils.hasText(serviceToUse)) {
            LOGGER.debug("Request has no service associated with it.");
            return null;
        }

        if (!StringUtils.hasText(loa)) {
            LOGGER.debug("Request has no service associated with it.");
            return null;
        }

        if (!supportedLevelsOfAuthentication.contains(loa)) {
            LOGGER.debug("Multifactor authentication service does not support [{}] parameter value [{}].", CONST_PARAM_LOA, loa);
            return null;
        }

        final String id = cleanupUrl(serviceToUse);
        final String artifactId = request.getParameter(CONST_PARAM_TICKET);

        final MultiFactorAuthenticationService svc = new MultiFactorAuthenticationService(id, serviceToUse,
                artifactId, httpClient, loa);
        LOGGER.debug("Created multifactor authentication request for [{}] with [{}] as [{]}.",
                svc.getId(), CONST_PARAM_LOA, svc.getLOA());
        return svc;
    }
}
