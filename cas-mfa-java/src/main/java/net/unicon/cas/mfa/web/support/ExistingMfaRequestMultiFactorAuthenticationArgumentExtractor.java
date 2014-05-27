package net.unicon.cas.mfa.web.support;

import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.web.support.ArgumentExtractor;

import javax.servlet.http.HttpServletRequest;

import java.util.List;
import java.util.Set;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD;

/**
 * The multifactor authentication argument extractor, responsible to
 * instruct CAS with the constructed instance of a {@link org.jasig.cas.authentication.principal.WebApplicationService}
 * that is supported based on the configured {@link #supportedAuthenticationMethods}.
 * <p/>
 * The requested authentication method discovery in this implementation is based on registered service extra attribute <b>authn_method</b>
 * <p/>
 * This implementation first checks if the target registered service contains the supported authentication method attribute
 * and uses that to create an mfa supporting service. If that is not the case, only then it delegates to a wrapped
 * <code>MultiFactorAuthenticationArgumentExtractor</code>
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public final class ExistingMfaRequestMultiFactorAuthenticationArgumentExtractor extends
        AbstractMultiFactorAuthenticationArgumentExtractor {

    /**
     * Ctor.
     *
     * @param authnMethods authnMethods
     * @param supportedProtocols supportedProtocols
     */
    public ExistingMfaRequestMultiFactorAuthenticationArgumentExtractor(final List<String> authnMethods,
                                                                        final Set<ArgumentExtractor> supportedProtocols) {
        super(authnMethods, supportedProtocols);
    }

    @Override
    protected WebApplicationService extractServiceInternal(final HttpServletRequest request) {
        logger.debug("Attempting to extract multifactor authentication method from potentially existing mfa request...");

        final MultiFactorAuthenticationRequestContext mfaRequest =
                MultiFactorAuthenticationRequestContext.class.cast(request.getAttribute("mfaRequest"));

        if (mfaRequest == null) {
            logger.debug("No [{}] is bound to the request attribute [{}]. Delegating to the next argument extractor in the chain...",
                    MultiFactorAuthenticationRequestContext.class.getSimpleName(), "mfaRequest");
            return null;
        }

        final String authenticationMethod = mfaRequest.getAuthenticationMethod();
        final WebApplicationService targetService = mfaRequest.getTargetService();

        verifyAuthenticationMethod(authenticationMethod, targetService, request);

        final MultiFactorAuthenticationSupportingWebApplicationService svc =
                new DefaultMultiFactorAuthenticationSupportingWebApplicationService(
                        targetService.getId(), targetService.getId(), targetService.getArtifactId(),
                        getHttpClientIfSingleSignOutEnabled(),
                        authenticationMethod, mfaRequest.getAuthenticationMethodSource());

        logger.debug("Created multifactor authentication request for [{}] with [{}] as [{}] and authentication method definition source [{}].",
                svc.getId(), CONST_PARAM_AUTHN_METHOD,
                svc.getAuthenticationMethod(),
                mfaRequest.getAuthenticationMethodSource());

        return svc;
    }
}
