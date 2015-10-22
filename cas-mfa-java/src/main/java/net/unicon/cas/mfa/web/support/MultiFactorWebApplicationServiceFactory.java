package net.unicon.cas.mfa.web.support;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource;
import org.jasig.cas.authentication.principal.Response.ResponseType;

/**
 * Factory abstraction for creating instances of
 * {@link net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService}.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public interface MultiFactorWebApplicationServiceFactory {


    /**
     * Create an instance of {@link net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService}.
     *
     * @param id service id
     * @param originalUrl originalUrl
     * @param artifactId artifactId
     * @param authnMethod authentication method
     * @param authenticationMethodSource authentication method source
     *
     * @return an instance of {@link net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService}
     */
    MultiFactorAuthenticationSupportingWebApplicationService create(String id,
                                                                    String originalUrl,
                                                                    String artifactId,
                                                                    ResponseType responseType,
                                                                    String authnMethod,
                                                                    AuthenticationMethodSource authenticationMethodSource);


}
