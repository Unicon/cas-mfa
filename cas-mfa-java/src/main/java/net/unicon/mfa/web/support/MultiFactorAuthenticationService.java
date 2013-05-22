package net.unicon.mfa.web.support;

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
 * The service.
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

    /**
     * Some data.
     */
    protected MultiFactorAuthenticationService(final String id, final String originalUrl,
            final String artifactId, final HttpClient httpClient) {
        super(id, originalUrl, artifactId, httpClient);
        this.wrapperService = new SimpleWebApplicationServiceImpl(id, httpClient);
    }

    @Override
    public final Response getResponse(final String ticketId) {
        return wrapperService.getResponse(ticketId);
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
            LOGGER.debug("Request does not support loa setting [{}].", loa);
            return null;
        }

        final String id = cleanupUrl(serviceToUse);
        final String artifactId = request.getParameter(CONST_PARAM_TICKET);

        return new MultiFactorAuthenticationService(id, serviceToUse, artifactId, httpClient);
    }
}
