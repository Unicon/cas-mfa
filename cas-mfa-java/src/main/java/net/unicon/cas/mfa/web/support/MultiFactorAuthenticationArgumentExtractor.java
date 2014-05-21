package net.unicon.cas.mfa.web.support;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.web.support.ArgumentExtractor;
import org.springframework.util.StringUtils;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource;

/**
 * The multifactor authentication argument extractor, responsible to
 * instruct CAS with the constructed instance of a {@link WebApplicationService}
 * that is supported based on the configured {@link #supportedAuthenticationMethods}.
 *
 * The requested authentication method discovery in this implementation is based on HTTP request parameter <b>authn_method</b>
 *
 * @author Misagh Moayyed
 */
public final class MultiFactorAuthenticationArgumentExtractor extends AbstractMultiFactorAuthenticationArgumentExtractor {

    /**
     * Ctor.
     *
     * @param authnMethods authn methods
     * @param supportedProtocols supported protocols
     */
    public MultiFactorAuthenticationArgumentExtractor(final List<String> authnMethods, final Set<ArgumentExtractor> supportedProtocols) {
        super(authnMethods, supportedProtocols);
    }

    @Override
    protected WebApplicationService extractServiceInternal(final HttpServletRequest request) {
        logger.debug("Attempting to extract multifactor authentication parameters from the request");

        final WebApplicationService targetService = getTargetService(request);
        if (targetService == null) {
            return null;
        }

        final String authenticationMethod =
                request.getParameter(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD);

        if (!StringUtils.hasText(authenticationMethod)) {
            logger.debug("Request has no request parameter [{}]",
                    MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD);
            return null;
        }

        verifyAuthenticationMethod(authenticationMethod, targetService, request);

        final MultiFactorAuthenticationSupportingWebApplicationService svc =
                new DefaultMultiFactorAuthenticationSupportingWebApplicationService(
                        targetService.getId(), targetService.getId(), targetService.getArtifactId(),
                        getHttpClientIfSingleSignOutEnabled(),
                        authenticationMethod, AuthenticationMethodSource.REQUEST_PARAM);
        logger.debug("Created multifactor authentication request for [{}] with [{}] as [{}].",
                svc.getId(), MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD,
                svc.getAuthenticationMethod());
        return svc;
    }
}
