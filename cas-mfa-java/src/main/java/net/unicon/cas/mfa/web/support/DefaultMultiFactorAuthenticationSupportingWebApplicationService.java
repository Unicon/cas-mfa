package net.unicon.cas.mfa.web.support;

import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.jasig.cas.authentication.principal.AbstractWebApplicationService;
import org.jasig.cas.authentication.principal.DefaultResponse;
import org.jasig.cas.authentication.principal.Response;
import org.jasig.cas.authentication.principal.Response.ResponseType;
import org.jasig.cas.authentication.principal.SimpleWebApplicationServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import javax.validation.constraints.NotNull;
import java.util.HashMap;

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
    private static final Logger LOGGER =
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
     *
     * @param id the service id, potentially with a jsessionid; still needing excised
     * @param originalUrl the service url
     * @param artifactId the artifact id
     * @param responseType the HTTP method for the response
     * @param authnMethod the authentication method required for this service
     */
    public DefaultMultiFactorAuthenticationSupportingWebApplicationService(final String id, final String originalUrl,
                                                                           final String artifactId, final ResponseType responseType,
                                                                           @NotNull final String authnMethod) {
        super(cleanupUrl(id), originalUrl, artifactId);
        this.wrapperService = new SimpleWebApplicationServiceImpl(id);
        this.authenticationMethod = authnMethod;
        this.responseType = responseType;
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
     * @param authnMethod the authentication method required for this service
     * @param authenticationMethodSource the authentication method source for this service
     */
    public DefaultMultiFactorAuthenticationSupportingWebApplicationService(
            final String id, final String originalUrl,
            final String artifactId, final ResponseType responseType,
            @NotNull final String authnMethod,
            @NotNull final AuthenticationMethodSource authenticationMethodSource) {
        this(id, originalUrl, artifactId, responseType, authnMethod);
        this.authenticationMethodSource = authenticationMethodSource;
    }

    public Response getResponse(final String ticketId) {
        final HashMap parameters = new HashMap();
        if(StringUtils.hasText(ticketId)) {
            parameters.put("ticket", ticketId);
        }

        return ResponseType.POST == this.responseType ? DefaultResponse.getPostResponse(this.getOriginalUrl(), parameters):
                DefaultResponse.getRedirectResponse(this.getOriginalUrl(), parameters);
    }

    @Override
    public String getAuthenticationMethod() {
        return this.authenticationMethod;
    }

    @Override
    public AuthenticationMethodSource getAuthenticationMethodSource() {
        return this.authenticationMethodSource;
    }
}
