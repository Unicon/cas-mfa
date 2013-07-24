package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.addons.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.web.support.WebUtils;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * Determines whether the login flow needs to branch *now* to honor the authentication method requirements of
 * {@link MultiFactorAuthenticationSupportingWebApplicationService}.
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
 * <p>
 * <ol>
 *  <li>If an authentication context does not exist
 *  (i.e., the user does not have an existing single sign-on session with a record of a prior authentication),
 *  continue the login flow as usual by firing the `requireTgt` event.</li>
 *  <li>If an authentication context exists without any authentication method decoration, fire the
 *  `requireMfa` event indicating that an exceptional flow is required to fulfill the service's authentication
 *  requirements</li>
 *  <li>If an authentication context exists with an authentication method decoration indicating an authentication
 *  method other than that required by the service, fire the `requireMfa` event indicating that an exceptional flow
 *  is required to fulfill the service's authentication requirements.</li>
 *  <li>Otherwise, fire the `requireTgt` event to continue the login flow as per usual.</li>
 * </ol>
 *
 * This means that in the case where there is not an existing single sign-on session, this Action will continue
 * the login flow as per normal <strong>even though additional authentication will be required
 * later in the flow to fulfill the authentication requirements of the CAS-using service</strong>.
 *
 * @author Misagh Moayyed
 */
public final class ValidateInitialMultiFactorAuthenticationRequestAction extends AbstractAction {

    /** The Constant EVENT_ID_REQUIRE_MFA. */
    public static final String EVENT_ID_REQUIRE_MFA = "mfa_";

    /** The Constant EVENT_ID_REQUIRE_TGT. */
    public static final String EVENT_ID_REQUIRE_TGT = "requireTgt";

    /** The authentication support. */
    private final AuthenticationSupport authenticationSupport;

    /**
     * Instantiates a new validate initial multifactor authentication request action.
     *
     * @param authSupport the authN support
     */
    public ValidateInitialMultiFactorAuthenticationRequestAction(final AuthenticationSupport authSupport) {
        this.authenticationSupport = authSupport;
    }

    /* (non-Javadoc)
     * @see org.springframework.webflow.action.AbstractAction#doExecute(org.springframework.webflow.execution.RequestContext)
     */
    @Override
    protected Event doExecute(final RequestContext context) throws Exception {

        final Service svc = WebUtils.getService(context);

        /*
         * If the service is null
         * or does not implement the interface indicating what authentication method it requires
         * proceed with normal login flow.
         */
        if (svc == null || !(svc instanceof MultiFactorAuthenticationSupportingWebApplicationService)) {
            logger.trace("Service null or does not implement authentication method requiring interface");
            return new Event(this, EVENT_ID_REQUIRE_TGT);
        }

        final MultiFactorAuthenticationSupportingWebApplicationService mfaSvc =
                (MultiFactorAuthenticationSupportingWebApplicationService) svc;

        final String requiredAuthenticationMethod = mfaSvc.getAuthenticationMethod();

        // place the authentication method in the appropriate scope
        MultiFactorRequestContextUtils.setRequiredAuthenticationMethod(context, requiredAuthenticationMethod);
        logger.trace("Service [" + mfaSvc.getId() + "] requires authentication method ["
                + requiredAuthenticationMethod + "]");

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
        if (StringUtils.isBlank(requiredAuthenticationMethod)) {
            logger.trace("Since required authentication method is blank, proceed flow normally.");
            return new Event(this, EVENT_ID_REQUIRE_TGT);
        }

        final Authentication authentication = this.authenticationSupport.getAuthenticationFrom(tgt);

        /*
         * If somehow the TGT were to have no authentication, then interpret as an existing SSO session insufficient
         * to fulfill the requirements of this service, and branch to fulfill the authentication requirement.
         */
        if (authentication == null) {
            logger.warn("TGT had no Authentication, which is odd.  "
                    + "Proceeding as if additional authentication required.");
            return new Event(this, getMultiFactorEventIdByAuthenticationMethod(requiredAuthenticationMethod));
        }

        final String previouslyAchievedAuthenticationMethod = (String) authentication.getAttributes().get(
                MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD);

        /*
         * If the recorded authentication method from the prior Authentication matches the authentication method
         * required to access the CAS-using service, proceed with the normal authentication flow.
         */
        if (StringUtils.equals(previouslyAchievedAuthenticationMethod, requiredAuthenticationMethod)) {
            logger.trace("Authentication method [" + requiredAuthenticationMethod + "] previously fulfilled; "
                    + "proceeding flow as per normal.");
            return new Event(this, EVENT_ID_REQUIRE_TGT);
        }

        logger.trace("Recorded authentication method [" + previouslyAchievedAuthenticationMethod + "] does not match "
                + "now-required authentication method [" + requiredAuthenticationMethod + "]; "
                + "branching to prompt for required authentication method.");
        return new Event(this, getMultiFactorEventIdByAuthenticationMethod(requiredAuthenticationMethod));

    }

    private String getMultiFactorEventIdByAuthenticationMethod(final String authnMethod) {
        return EVENT_ID_REQUIRE_MFA + authnMethod;
    }
}
