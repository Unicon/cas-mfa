package net.unicon.cas.mfa.web.support;

import org.apache.commons.lang.builder.HashCodeBuilder;
import org.jasig.cas.authentication.principal.AbstractWebApplicationService;
import org.jasig.cas.authentication.principal.GoogleAccountsService;
import org.jasig.cas.authentication.principal.Response;
import org.jasig.cas.authentication.principal.Response.ResponseType;
import org.jasig.cas.authentication.principal.SamlService;
import org.jasig.cas.authentication.principal.SimpleWebApplicationServiceImpl;
import org.jasig.cas.util.HttpClient;
import org.jasig.cas.web.support.GoogleAccountsArgumentExtractor;
import org.jasig.cas.web.support.SamlArgumentExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.execution.RequestContextHolder;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
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
        implements MultiFactorAuthenticationSupportingWebApplicationService {

    /**
     * The logger instance.
     **/
    protected static final Logger LOGGER =
            LoggerFactory.getLogger(DefaultMultiFactorAuthenticationSupportingWebApplicationService.class);

    private static final long serialVersionUID = 7537062414761087535L;

    /**
     * The wrapped service.
     */
    private final SimpleWebApplicationServiceImpl wrapperService;

    /**
     * The authentication method.
     */
    private final String authenticationMethod;

    /**
     * The authentication method source.
     */
    private AuthenticationMethodSource authenticationMethodSource;

    /**
     * The type of HTTP response.
     **/
    private final ResponseType responseType;


    /**
     * Create an instance of {@link DefaultMultiFactorAuthenticationSupportingWebApplicationService}.
     *
     * @param id           the service id, potentially with a jsessionid; still needing excised
     * @param originalUrl  the service url
     * @param artifactId   the artifact id
     * @param responseType the HTTP method for the response
     * @param httpClient   http client to process requests
     * @param authnMethod  the authentication method required for this service
     */
    public DefaultMultiFactorAuthenticationSupportingWebApplicationService(final String id, final String originalUrl,
                                                                           final String artifactId, final ResponseType responseType,
                                                                           final HttpClient httpClient, @NotNull final String authnMethod) {
        super(id, originalUrl, artifactId, httpClient);
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
     * @param id                         the service id, potentially with a jsessionid; still needing excised
     * @param originalUrl                the service url
     * @param artifactId                 the artifact id
     * @param responseType               the HTTP method for the response
     * @param httpClient                 http client to process requests
     * @param authnMethod                the authentication method required for this service
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

        final RequestContext requestContext = RequestContextHolder.getRequestContext();
        LOGGER.debug("getRequestParameters = " + requestContext.getRequestParameters());

        final HttpServletRequest req = (HttpServletRequest) requestContext.getExternalContext().getNativeRequest();
        LOGGER.debug("getRequestParameters from native request = " + req.getQueryString());

        final String relayState = req.getParameter("RelayState");
        LOGGER.debug("getRequestParameters relayState = " + relayState);

        final String samlRequest = req.getParameter("SAMLRequest");
        LOGGER.debug("xmlRequest = " + samlRequest);

        final String samlTarget = req.getParameter("TARGET");
        LOGGER.debug("samlTarget = " + samlTarget);

        if (StringUtils.hasText(ticketId)) {
            parameters.put(CONST_PARAM_TICKET, ticketId);
        }
        if (StringUtils.hasText(samlRequest)) {
            LOGGER.debug("working through GoogleAccounts response");
            try {
                final GoogleAccountsArgumentExtractor googleAccountsArgumentExtractor =
                        getBean("googleAccountsArgumentExtractor",
                                GoogleAccountsArgumentExtractor.class);
                final GoogleAccountsService googleAccountsService =
                        (GoogleAccountsService) googleAccountsArgumentExtractor.extractService(req);
                googleAccountsService.setPrincipal(getPrincipal());
                final Response rs = googleAccountsService.getResponse(ticketId);
                final String samlResponse = rs.getAttributes().get("SAMLResponse");
                if (StringUtils.hasText(samlResponse)) {
                    parameters.put("SAMLResponse", samlResponse);
                    parameters.put("RelayState", relayState);

                    LOGGER.debug("sendingGoogleAccounts response");
                    return Response.getPostResponse(getOriginalUrl(), parameters);
                }
            } catch (final Exception e) {
                LOGGER.error(e.getMessage());
            }
        }
        if (StringUtils.hasText(samlTarget)) {
            try {
                LOGGER.debug("working through Saml (1.1) response");
                final SamlArgumentExtractor samlArgumentExtractor =
                        getBean("samlArgumentExtractor",
                                SamlArgumentExtractor.class);
                final SamlService samlService =
                        (SamlService) samlArgumentExtractor.extractService(req);
                samlService.setPrincipal(getPrincipal());

                parameters.put("SAMLart", ticketId);
                parameters.put("TARGET", getOriginalUrl());

                LOGGER.debug("sending Saml (1.1) response");
                return Response.getRedirectResponse(getOriginalUrl(), parameters);

            } catch (final Exception e) {
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

    /**
     * Gets the requested bean from the application context.
     *
     * @param name  bean name
     * @param <T>   bean type
     * @param clazz the expected class type
     * @return the bean instance
     */
    private <T> T getBean(final String name, final Class<T> clazz) {
        final RequestContext context = RequestContextHolder.getRequestContext();
        //return context.getActiveFlow().getApplicationContext().getBean(name, clazz);
        return context.getActiveFlow().getApplicationContext().getBean(clazz);
    }

}
