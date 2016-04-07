package net.unicon.cas.mfa.web.support;

import org.apache.commons.lang.builder.HashCodeBuilder;
import org.jasig.cas.authentication.principal.*;
import org.jasig.cas.util.HttpClient;
import org.jasig.cas.authentication.principal.Response.ResponseType;
import org.jasig.cas.web.support.GoogleAccountsArgumentExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.execution.RequestContextHolder;
import javax.validation.constraints.NotNull;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

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
        implements MultiFactorAuthenticationSupportingWebApplicationService    {

    /** The logger instance. **/
    protected static final Logger LOGGER =
            LoggerFactory.getLogger(DefaultMultiFactorAuthenticationSupportingWebApplicationService.class);

    private static final long serialVersionUID = 7537062414761087535L;

    /** The wrapped service. */
    private final SimpleWebApplicationServiceImpl wrapperService;

    /** The authentication method. */
    private final String authenticationMethod;

    /** The authentication method source. */
    private AuthenticationMethodSource authenticationMethodSource;

    /** The type of HTTP response. **/
    private final ResponseType responseType;



    /**
     * Create an instance of {@link DefaultMultiFactorAuthenticationSupportingWebApplicationService}.
     *  @param id the service id, potentially with a jsessionid; still needing excised
     * @param originalUrl the service url
     * @param artifactId the artifact id
     * @param responseType the HTTP method for the response
     * @param httpClient http client to process requests
     * @param authnMethod the authentication method required for this service
     */
    public DefaultMultiFactorAuthenticationSupportingWebApplicationService(final String id, final String originalUrl,
                                                                           final String artifactId, final ResponseType responseType, final HttpClient httpClient, @NotNull final String authnMethod ) {
        super( id, originalUrl, artifactId, httpClient);


        //final HttpServletRequest request = HttpServletRequest.class.cast(context.getEnvironment().getNativeRequest());

        LOGGER.debug("id = " + id);
        LOGGER.debug("originalUrl = " + originalUrl);
        LOGGER.debug("artifactId = " + artifactId);
        LOGGER.debug("cleanupUrl(id) = " + cleanupUrl(id));
        LOGGER.debug("responseType = " + responseType);

       //super(cleanupUrl(id), originalUrl, artifactId, httpClient);
        this.wrapperService = new SimpleWebApplicationServiceImpl(id, httpClient);

        this.authenticationMethod = authnMethod;
        this.responseType = responseType;

       // final List<ArgumentExtractor> list = context.getBean("argumentExtractors", List.class);


        }



    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        final DefaultMultiFactorAuthenticationSupportingWebApplicationService that =
                (DefaultMultiFactorAuthenticationSupportingWebApplicationService) o;

        if (!this.getAuthenticationMethod().equals(that.getAuthenticationMethod())) {
            return false;
        }
        if (this.getAuthenticationMethodSource() != that.getAuthenticationMethodSource()) {
            return false;
        }
        return this.getId().equals(that.getId());
    }

    @Override
    public int hashCode() {
        final HashCodeBuilder builder = new HashCodeBuilder(13, 133);
        return builder.append(this.getAuthenticationMethod())
                      .append(this.getAuthenticationMethodSource())
                      .append(this.getId())
                      .toHashCode();
    }

    /**
     * Create an instance of {@link DefaultMultiFactorAuthenticationSupportingWebApplicationService}.
     *
     * @param id the service id, potentially with a jsessionid; still needing excised
     * @param originalUrl the service url
     * @param artifactId the artifact id
     * @param responseType the HTTP method for the response
     * @param httpClient http client to process requests
     * @param authnMethod the authentication method required for this service
     * @param authenticationMethodSource the authentication method source for this service
     */
    public DefaultMultiFactorAuthenticationSupportingWebApplicationService(
            final String id, final String originalUrl,
            final String artifactId, final ResponseType responseType, final HttpClient httpClient,
            @NotNull final String authnMethod,
            @NotNull final AuthenticationMethodSource authenticationMethodSource) {
        this(id, originalUrl, artifactId, responseType, httpClient, authnMethod);
        this.authenticationMethodSource = authenticationMethodSource;
    }

    @Override
    public Response getResponse(final String ticketId) {
        final Map<String, String> parameters = new HashMap<String, String>();

        RequestContext requestContext =  RequestContextHolder.getRequestContext();
        LOGGER.debug("$$$$$$ getRequestParameters = " + requestContext.getRequestParameters());

        HttpServletRequest req = (HttpServletRequest )requestContext.getExternalContext().getNativeRequest();
        LOGGER.debug("$$$$$$ getRequestParameters from native request = " + req.getQueryString());

        final String relayState = req.getParameter("RelayState");
        LOGGER.debug("$$$$$$ getRequestParameters relayState = " + relayState);
        final String samlRequest =  req.getParameter("SAMLRequest");
        LOGGER.debug("$$$$$$ xmlRequest = " + samlRequest);

        if (StringUtils.hasText(ticketId)) {
            parameters.put(CONST_PARAM_TICKET, ticketId);
        }
        if(StringUtils.hasText(samlRequest)) {
            try {
                GoogleAccountsArgumentExtractor googleAccountsArgumentExtractor = getBean("googleAccountsArgumentExtractor", GoogleAccountsArgumentExtractor.class);
                GoogleAccountsService googleAccountsService = (GoogleAccountsService) googleAccountsArgumentExtractor.extractService(req);
                googleAccountsService.setPrincipal(getPrincipal());
                Response rs = googleAccountsService.getResponse(ticketId);
                String samlResponse = rs.getAttributes().get("SAMLResponse");
                if (StringUtils.hasText(samlResponse)) {
                    parameters.put("SAMLResponse", samlResponse);
                    parameters.put("RelayState", relayState);
                    return Response.getPostResponse(getOriginalUrl(), parameters);
                }
            }catch (Exception e)
            {
                LOGGER.error(e.getMessage());
            }
 
        }

        if (ResponseType.POST == this.responseType) {
            return Response.getPostResponse(getOriginalUrl(), parameters);
        }
        return Response.getRedirectResponse(getOriginalUrl(), parameters);
    }

    @Override
    public String getAuthenticationMethod() {
        return this.authenticationMethod;
    }

    @Override
    public AuthenticationMethodSource getAuthenticationMethodSource() {
        return this.authenticationMethodSource;
    }



    public <T> T getBean(String name, Class<T> clazz) {
        RequestContext context = RequestContextHolder.getRequestContext();
        //return context.getActiveFlow().getApplicationContext().getBean(name, clazz);
        return context.getActiveFlow().getApplicationContext().getBean(clazz);
    }

}
