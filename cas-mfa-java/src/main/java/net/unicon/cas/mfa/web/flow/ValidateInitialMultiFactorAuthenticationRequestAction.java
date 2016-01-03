package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.addons.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationTransactionContext;
import net.unicon.cas.mfa.authentication.RequestedAuthenticationMethodRankingStrategy;
import net.unicon.cas.mfa.util.MultiFactorUtils;
import net.unicon.cas.mfa.web.flow.event.MultiFactorAuthenticationSpringWebflowEventBuilder;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import org.apache.commons.lang3.StringUtils;
import org.jasig.cas.CasProtocolConstants;
import org.jasig.cas.authentication.Authentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.util.Set;

/**
 * Determines whether the login flow needs to branch *now* to honor the authentication method requirements of
 *
 *
 * If the Service expresses a requirement for how the user must authenticate,
 * and there's an existing single sign-on session, and there is not a record in the user's
 * single sign-on session of having already fulfilled that requirement, then fires the `requireMfa` event indicating
 * that exceptional handling is required.  Otherwise (i.e., if no exceptional authentication method is required,
 * or there is no existing single sign-on session,
 * or the required exceptional authentication method is already fulfilled) then fire the `requireTgt` event indicating
 * that the login flow should proceed as per normal.
 *
 * More explicitly:
 *
 *
 * <ol>
 * <li>If an authentication context does not exist
 * (i.e., the user does not have an existing single sign-on session with a record of a prior authentication),
 * continue the login flow as usual by firing the `requireTgt` event.</li>
 * <li>If an authentication context exists without any authentication method decoration, fire the
 * `requireMfa` event indicating that an exceptional flow is required to fulfill the service's authentication
 * requirements</li>
 * <li>If an authentication context exists with an authentication method decoration indicating an authentication
 * method other than that required by the service, fire the `requireMfa` event indicating that an exceptional flow
 * is required to fulfill the service's authentication requirements.</li>
 * <li>Otherwise, fire the `requireTgt` event to continue the login flow as per usual.</li>
 * </ol>
 *
 * This means that in the case where there is not an existing single sign-on session, this Action will continue
 * the login flow as per normal <strong>even though additional authentication will be required
 * later in the flow to fulfill the authentication requirements of the CAS-using service</strong>.
 *
 * @author Misagh Moayyed
 */
public final class ValidateInitialMultiFactorAuthenticationRequestAction extends AbstractAction {

    private final Logger logger = LoggerFactory.getLogger(ValidateInitialMultiFactorAuthenticationRequestAction.class);

    /**
     * The Constant EVENT_ID_REQUIRE_TGT.
     */
    public static final String EVENT_ID_REQUIRE_TGT = "requireTgt";

    /**
     * The authentication support.
     */
    private final AuthenticationSupport authenticationSupport;

    /**
     * Authentication method ranking strategy.
     */
    private final RequestedAuthenticationMethodRankingStrategy authnMethodRankingStrategy;

    /**
     * Instantiates a new validate initial multifactor authentication request action.
     *
     * @param authSupport the authN support
     * @param authenticationMethodRankingStrategy authenticationMethodRankingStrategy
     */
    public ValidateInitialMultiFactorAuthenticationRequestAction(final AuthenticationSupport authSupport,
                           final RequestedAuthenticationMethodRankingStrategy authenticationMethodRankingStrategy) {
        this.authenticationSupport = authSupport;
        this.authnMethodRankingStrategy = authenticationMethodRankingStrategy;
    }

    /* (non-Javadoc)
     * @see org.springframework.webflow.action.AbstractAction#doExecute(org.springframework.webflow.execution.RequestContext)
     */
    @Override
    protected Event doExecute(final RequestContext context) throws Exception {
        final MultiFactorAuthenticationTransactionContext mfaTx = MultiFactorRequestContextUtils.getMfaTransaction(context);
        if (mfaTx == null) {
            return new Event(this, EVENT_ID_REQUIRE_TGT);
        }
        final MultiFactorAuthenticationSupportingWebApplicationService mfaService =
                this.authnMethodRankingStrategy.computeHighestRankingAuthenticationMethod(mfaTx);

        final String requestedAuthenticationMethod = mfaService != null ? mfaService.getAuthenticationMethod() : null;
        final String tgt = MultiFactorRequestContextUtils.getTicketGrantingTicketId(context);

        /*
         * If the TGT is blank i.e. there is no existing SSO session, proceed with normal login flow
         * (Note that flow may need interrupted later if the CAS-using service requires an authentication method
         *  not fulfilled by the normal login flow)
         */
        if (StringUtils.isBlank(tgt)) {
            logger.trace("TGT is blank; proceed flow normally.");
            return new Event(this, EVENT_ID_REQUIRE_TGT);
        }

        /*
         * If the authentication method the CAS-using service has specified is blank,
         * proceed with the normal login flow.
         */
        if (StringUtils.isBlank(requestedAuthenticationMethod)) {
            logger.trace("Since required authentication method is blank, proceed flow normally.");
            return new Event(this, EVENT_ID_REQUIRE_TGT);
        }

        logger.trace("Service [{}] requires authentication method [{}]", mfaTx.getTargetServiceId(), requestedAuthenticationMethod);
        final Authentication authentication = this.authenticationSupport.getAuthenticationFrom(tgt);

        /*
         * If somehow the TGT were to have no authentication, then interpret as an existing SSO session insufficient
         * to fulfill the requirements of this service, and branch to fulfill the authentication requirement.
         */
        if (authentication == null) {
            logger.warn("TGT had no Authentication, which is odd. "
                    + "Proceeding as if additional authentication required.");

            //Place the ranked mfa service into the flow scope to be available in the actual mfa subflows
            MultiFactorRequestContextUtils.setMultifactorWebApplicationService(context, mfaService);
            return new Event(this, getMultiFactorEventIdByAuthenticationMethod(requestedAuthenticationMethod));
        }

        final Set<String> previouslyAchievedAuthenticationMethods =
                MultiFactorUtils.getSatisfiedAuthenticationMethods(authentication);

        /*
         * If any of the recorded authentication methods from the prior Authentication are 'stronger'
         * than the authentication method requested to access the CAS-using service, proceed with the normal authentication flow.
         */
        if (this.authnMethodRankingStrategy
                .anyPreviouslyAchievedAuthenticationMethodsStrongerThanRequestedOne(previouslyAchievedAuthenticationMethods,
                        requestedAuthenticationMethod)) {
            logger.trace("Authentication method [{}] is EQUAL -- OR -- WEAKER than any previously fulfilled methods [{}]; "
                    + "proceeding with flow normally...", requestedAuthenticationMethod, previouslyAchievedAuthenticationMethods);
            return new Event(this, EVENT_ID_REQUIRE_TGT);
        }

        if (context.getRequestParameters().get(CasProtocolConstants.PARAMETER_RENEW) != null) {
            return new Event(this, EVENT_ID_REQUIRE_TGT);
        }

        logger.trace("Authentication method [{}] is STRONGER than any previously fulfilled methods [{}]; "
                + "branching to prompt for required authentication method.",
                requestedAuthenticationMethod, previouslyAchievedAuthenticationMethods);

        //Place the ranked mfa service into the flow scope to be available in the actual mfa subflows
        MultiFactorRequestContextUtils.setMultifactorWebApplicationService(context, mfaService);
        return new Event(this, getMultiFactorEventIdByAuthenticationMethod(requestedAuthenticationMethod));
    }

    /**
     * Construct the next MFA event id based on the given authentication method.
     *
     * @param authnMethod the authentication method provided
     *
     * @return the next event in the flow, that is effectively the value of
     * {@link MultiFactorAuthenticationSpringWebflowEventBuilder#MFA_EVENT_ID_PREFIX}
     * prepended to the authentication method.
     */
    private static String getMultiFactorEventIdByAuthenticationMethod(final String authnMethod) {
        return MultiFactorAuthenticationSpringWebflowEventBuilder.MFA_EVENT_ID_PREFIX + authnMethod;
    }
}
