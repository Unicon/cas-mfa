package net.unicon.cas.mfa.web.support;

import net.unicon.cas.mfa.authentication.AuthenticationMethodTranslator;
import net.unicon.cas.mfa.authentication.StubAuthenticationMethodTranslator;
import org.apache.commons.lang.StringUtils;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.web.support.ArgumentExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource;
import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD;

/**
 * Abstract extractor containing common functionality pertaining to authentication methods verification and target service extraction
 * that subclasses delegate to.
 *
 * @author Misagh Moayyed
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public abstract class AbstractMultiFactorAuthenticationArgumentExtractor implements ArgumentExtractor {

    /**
     * Target argument extractors.
     */
    private final List<ArgumentExtractor> supportedArgumentExtractors;

    /**
     * Factory for mfa services.
     */
    private final MultiFactorWebApplicationServiceFactory mfaWebApplicationServiceFactory;

    /**
     * This log would be replaced by the superclass's log if CAS-1332 realized.
     */
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Authentication method verifier.
     */
    private final AuthenticationMethodVerifier authenticationMethodVerifier;

    /**
     * The Authentication method translator.
     */
    private AuthenticationMethodTranslator authenticationMethodTranslator = new StubAuthenticationMethodTranslator();
    /**
     * Ctor.
     * @param supportedArgumentExtractors supportedArgumentExtractors
     * @param mfaWebApplicationServiceFactory mfaWebApplicationServiceFactory
     * @param authenticationMethodVerifier authenticationMethodVerifier
     */
    public AbstractMultiFactorAuthenticationArgumentExtractor(final List<ArgumentExtractor> supportedArgumentExtractors,
                                                              final MultiFactorWebApplicationServiceFactory mfaWebApplicationServiceFactory,
                                                              final AuthenticationMethodVerifier authenticationMethodVerifier) {
        this.supportedArgumentExtractors = supportedArgumentExtractors;
        this.mfaWebApplicationServiceFactory = mfaWebApplicationServiceFactory;
        this.authenticationMethodVerifier = authenticationMethodVerifier;
    }

    @Override
    public final WebApplicationService extractService(final HttpServletRequest request) {
        final WebApplicationService targetService = getTargetService(request);
        if (targetService == null) {
            return null;
        }
        String authenticationMethod = this.getAuthenticationMethod(request, targetService);
        if (StringUtils.isBlank(authenticationMethod)) {
            return null;
        }
        authenticationMethod = this.authenticationMethodTranslator.translate(targetService, authenticationMethod);
        this.authenticationMethodVerifier.verifyAuthenticationMethod(authenticationMethod, targetService, request);

        final MultiFactorAuthenticationSupportingWebApplicationService mfaService =
                this.mfaWebApplicationServiceFactory.create(targetService.getId(), targetService.getId(), targetService.getArtifactId(),
                        authenticationMethod, getAuthenticationMethodSource());

        logger.debug("Created multifactor authentication service instance for [{}] with [{}] as [{}] "
                + "and authentication method definition source [{}].",
                mfaService.getId(), CONST_PARAM_AUTHN_METHOD,
                mfaService.getAuthenticationMethod(),
                mfaService.getAuthenticationMethodSource());

        return mfaService;
    }

    /**
     * Extract a target service. Delegates to wrapped argument extractors.
     *
     * @param request http request
     *
     * @return target service that would potentially be wrapped with an MFA supporting service
     */
    private WebApplicationService getTargetService(final HttpServletRequest request) {
        WebApplicationService targetService = null;
        for (final ArgumentExtractor extractor : this.supportedArgumentExtractors) {
            targetService = extractor.extractService(request);
            if (targetService != null) {
                logger.debug("[{}] intercepted the request successfully for multifactor authentication",
                        extractor);
                break;
            }
        }

        if (targetService == null) {
            logger.debug("Request is unable to identify the target application");
            return null;
        }
        return targetService;
    }

    public void setAuthenticationMethodTranslator(final AuthenticationMethodTranslator authenticationMethodTranslator) {
        this.authenticationMethodTranslator = authenticationMethodTranslator;
    }

    /**
     * Delegates to subclasses to resolve requested authentication method.
     *
     * @param request http request
     * @param targetService target service
     *
     * @return authentication method or null if not resolved
     */
    protected abstract String getAuthenticationMethod(HttpServletRequest request, WebApplicationService targetService);

    /**
     * Delegates to subclasses to resolve target authentication method source.
     *
     * @return target authentication method source.
     */
    protected abstract AuthenticationMethodSource getAuthenticationMethodSource();

}
