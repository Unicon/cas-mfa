package net.unicon.cas.mfa.web.support;

import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.web.support.ArgumentExtractor;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource;

/**
 * The multifactor authentication argument extractor, responsible to
 * instruct CAS with the constructed instance of a {@link WebApplicationService}.
 *
 * The requested authentication method discovery in this implementation is based on HTTP request parameter <b>authn_method</b>
 *
 * @author Misagh Moayyed
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public final class RequestParameterMultiFactorAuthenticationArgumentExtractor extends
        AbstractMultiFactorAuthenticationArgumentExtractor {


    /**
     * Ctor.
     *
     * @param supportedArgumentExtractors supported protocols by argument extractors
     * @param mfaWebApplicationServiceFactory mfaWebApplicationServiceFactory
     * @param authenticationMethodVerifier authenticationMethodVerifier
     */
    public RequestParameterMultiFactorAuthenticationArgumentExtractor(final List<ArgumentExtractor> supportedArgumentExtractors,
           final MultiFactorWebApplicationServiceFactory mfaWebApplicationServiceFactory,
           final AuthenticationMethodVerifier authenticationMethodVerifier) {

        super(supportedArgumentExtractors, mfaWebApplicationServiceFactory, authenticationMethodVerifier);
    }

    @Override
    protected String getAuthenticationMethod(final HttpServletRequest request, final WebApplicationService targetService) {
        logger.debug("Attempting to extract multifactor authentication parameters from the request");

        final String authenticationMethod =
                request.getParameter(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD);

        if (!StringUtils.hasText(authenticationMethod)) {
            logger.debug("Request has no request parameter [{}]. Delegating to the next argument extractor in the chain...",
                    MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD);
            return null;
        }
        return authenticationMethod;
    }

    @Override
    protected AuthenticationMethodSource getAuthenticationMethodSource() {
        return AuthenticationMethodSource.REQUEST_PARAM;
    }
}
