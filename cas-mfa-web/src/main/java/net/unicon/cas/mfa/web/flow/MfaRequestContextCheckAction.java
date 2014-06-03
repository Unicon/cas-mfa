package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext;
import net.unicon.cas.mfa.web.support.AuthenticationMethodVerifier;
import net.unicon.cas.mfa.web.support.MfaWebApplicationServiceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD;

/**
 * Action state that checks for the existence of {@link net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext}
 * and if found, creates an instance of {@link net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService}
 * and binds it to the flow scope under the <strong>service</strong> key to be accessed by downstream mfa subflow components.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public final class MfaRequestContextCheckAction extends AbstractAction {

    /**
     * Authentication method verifier.
     */
    private final AuthenticationMethodVerifier authenticationMethodVerifier;

    /**
     * Mfa service factory.
     */
    private final MfaWebApplicationServiceFactory mfaWebApplicationServiceFactory;

    /**
     * The logger.
     */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Ctor.
     *
     * @param authenticationMethodVerifier authenticationMethodVerifier
     * @param mfaWebApplicationServiceFactory mfaWebApplicationServiceFactory
     */
    public MfaRequestContextCheckAction(final AuthenticationMethodVerifier authenticationMethodVerifier,
                                        final MfaWebApplicationServiceFactory mfaWebApplicationServiceFactory) {

        this.authenticationMethodVerifier = authenticationMethodVerifier;
        this.mfaWebApplicationServiceFactory = mfaWebApplicationServiceFactory;
    }

    @Override
    protected Event doExecute(final RequestContext context) throws Exception {
        final MultiFactorAuthenticationRequestContext mfaRequest =
                MultiFactorAuthenticationRequestContext.class.cast(context.getConversationScope().get("mfaRequest"));

        if (mfaRequest != null) {
            final String authenticationMethod = mfaRequest.getAuthenticationMethod();
            //This should throw UnrecognizedAuthenticationMethodException if does not pass verification
            this.authenticationMethodVerifier.verifyAuthenticationMethod(authenticationMethod, mfaRequest.getTargetService(),
                    HttpServletRequest.class.cast(context.getExternalContext().getNativeRequest()));

            logger.info("There is an existing mfa request for service [{}] with a requested authentication method of [{}]",
                    mfaRequest.getTargetService().getId(), authenticationMethod);

            context.getFlowScope().put("service",
                    this.mfaWebApplicationServiceFactory.create(mfaRequest.getTargetService().getId(), mfaRequest.getTargetService().getId(),
                            mfaRequest.getTargetService().getArtifactId(), authenticationMethod, mfaRequest.getAuthenticationMethodSource())
            );

            logger.debug("Created multifactor authentication service instance for [{}] with [{}] as [{}] and authentication method definition source [{}].",
                    mfaRequest.getTargetService().getId(), CONST_PARAM_AUTHN_METHOD,
                    authenticationMethod,
                    mfaRequest.getAuthenticationMethodSource());

            logger.debug("Removing mfa request from conversation scope...");
            context.getConversationScope().remove("mfaRequest");
        }
        //No specific events are expected from this state
        return null;
    }
}
