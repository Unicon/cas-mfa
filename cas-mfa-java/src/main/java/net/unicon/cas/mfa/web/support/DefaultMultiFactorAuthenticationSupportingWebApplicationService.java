package net.unicon.cas.mfa.web.support;

import javax.validation.constraints.NotNull;

import org.jasig.cas.authentication.principal.AbstractWebApplicationService;
import org.jasig.cas.authentication.principal.Response;
import org.jasig.cas.authentication.principal.SimpleWebApplicationServiceImpl;
import org.jasig.cas.util.HttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The MultiFactorAuthenticationService is an extension of the generic CAS service
 * that delegates calls to {@link SimpleWebApplicationServiceImpl}. The only difference
 * is that it is only is activated when the request parameter {@link #CONST_PARAM_AUTHN_METHOD} is
 * present and its value is supported by the corresponding argument extractor.
 * <p>NOTE: The delegation is necessary because the {@link SimpleWebApplicationServiceImpl}
 * itself is marked as final. Future versions of CAS might make the class more available.
 *
 * @author Misagh Moayyed
 */
public final class DefaultMultiFactorAuthenticationSupportingWebApplicationService
        extends AbstractWebApplicationService
        implements MultiFactorAuthenticationSupportingWebApplicationService {

    /** The logger instance. **/
    protected static final Logger LOGGER =
            LoggerFactory.getLogger(DefaultMultiFactorAuthenticationSupportingWebApplicationService.class);

    private static final long serialVersionUID = 7537062414761087535L;



    private final SimpleWebApplicationServiceImpl wrapperService;

    private final String authenticationMethod;

    /**
     * Create an instance of {@link DefaultMultiFactorAuthenticationSupportingWebApplicationService}.
     *
     * @param id the service id, potentially with a jsessionid; still needing excised
     * @param originalUrl the service url
     * @param artifactId the artifact id
     * @param httpClient http client to process requests
     * @param authnMethod the authentication method required for this service
     */
    public DefaultMultiFactorAuthenticationSupportingWebApplicationService(final String id, final String originalUrl,
            final String artifactId, final HttpClient httpClient, @NotNull final String authnMethod) {
        super(cleanupUrl(id), originalUrl, artifactId, httpClient);
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
}
