package net.unicon.cas.mfa.web.support;

import org.jasig.cas.authentication.principal.Response.ResponseType;
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

    @Override
    public MultiFactorAuthenticationSupportingWebApplicationService create(final String id,
                                                                           final String originalUrl,
                                                                           final String artifactId,
                                                                           final ResponseType responseType,
                                                                           final String authenticationMethod,
                                                                           final AuthenticationMethodSource authenticationMethodSource) {

        Assert.notNull(authenticationMethod, "authnMethod cannot be null.");
        Assert.notNull(authenticationMethodSource, "authenticationMethodSource cannot be null.");

        return new DefaultMultiFactorAuthenticationSupportingWebApplicationService(
                id, originalUrl, artifactId, responseType,
                authenticationMethod, authenticationMethodSource);
    }

}
