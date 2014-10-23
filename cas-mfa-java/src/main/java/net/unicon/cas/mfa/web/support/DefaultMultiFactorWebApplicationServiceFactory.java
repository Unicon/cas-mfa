package net.unicon.cas.mfa.web.support;

import org.jasig.cas.util.HttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource;

/**
 * Default implementation of <code>MfaWebApplicationServiceFactory</code>.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public final class DefaultMultiFactorWebApplicationServiceFactory implements MultiFactorWebApplicationServiceFactory {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Whether single sign out is disabled or not.
     */
    private final boolean disableSingleSignOut;

    /**
     * Default instance of HttpClient.
     */
    private final HttpClient httpClient;

    /**
     * Ctor.
     *
     * @param disableSingleSignOut disableSingleSignOut flag
     * @param httpClient httpClient
     */
    public DefaultMultiFactorWebApplicationServiceFactory(final boolean disableSingleSignOut, final HttpClient httpClient) {
        this.disableSingleSignOut = disableSingleSignOut;
        this.httpClient = httpClient;
    }

    @Override
    public MultiFactorAuthenticationSupportingWebApplicationService create(final String id,
                                                                           final String originalUrl,
                                                                           final String artifactId,
                                                                           final String authenticationMethod,
                                                                           final AuthenticationMethodSource authenticationMethodSource) {

        Assert.notNull(authenticationMethod, "authnMethod cannot be null.");
        Assert.notNull(authenticationMethodSource, "authenticationMethodSource cannot be null.");

        return new DefaultMultiFactorAuthenticationSupportingWebApplicationService(
                id, originalUrl, artifactId,
                getHttpClientIfSingleSignOutEnabled(),
                authenticationMethod, authenticationMethodSource);
    }

    /**
     * Get httpClient.
     *
     * @return httpClient if single signout is enabled or null
     */
    private HttpClient getHttpClientIfSingleSignOutEnabled() {
        return !this.disableSingleSignOut ? this.httpClient : null;
    }


}
