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
 * the login flow as per normal <strong></strong>even though additional authentication will be required
 * later in the flow to fulfill the authentication requirements of the CAS-using service</strong>.
 *
 * @author Misagh Moayyed
 */
public final class ValidateInitialMultiFactorAuthenticationRequestAction extends AbstractAction {

    /** The Constant EVENT_ID_REQUIRE_MFA. */
    public static final String EVENT_ID_REQUIRE_MFA = "requireMfa";

    /** The Constant EVENT_ID_REQUIRE_TGT. */
    public static final String EVENT_ID_REQUIRE_TGT = "requireTgt";

    /** The authentication support. */
    private final AuthenticationSupport authenticationSupport;

    /**
     * Instantiates a new validate initial multi factor authentication request action.
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

        final String tgt = MultiFactorRequestContextUtils.getTicketGrantingTicketId(context);
        final Service svc = WebUtils.getService(context);

        if (!StringUtils.isBlank(tgt) && svc != null && svc instanceof MultiFactorAuthenticationSupportingWebApplicationService
                && !context.getRequestParameters().isEmpty()) {

            final MultiFactorAuthenticationSupportingWebApplicationService mfaSvc =
                    (MultiFactorAuthenticationSupportingWebApplicationService) svc;
            final Authentication authentication = this.authenticationSupport.getAuthenticationFrom(tgt);

            if (authentication != null) {
                final String authnMethod = (String) authentication.getAttributes().get(
                        MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD);

                /**
                 * If the requested authentication method exists, but CAS cannot provide an
                 * authentication method, require mfa.
                 */
                if (!StringUtils.isBlank(mfaSvc.getAuthenticationMethod()) && StringUtils.isBlank(authnMethod)) {
                    return new Event(this, EVENT_ID_REQUIRE_MFA);
                }

                /**
                 * If we have established an MFA session, and this is an Mfa authentication request,
                 * and if the authentication method remembered by the CAS server matches the
                 * authentication method requested by the service match, proceed normally.
                 */
                if (!StringUtils.isBlank(authnMethod) && !StringUtils.isBlank(mfaSvc.getAuthenticationMethod())
                        && authnMethod.equals(mfaSvc.getAuthenticationMethod())) {
                    return new Event(this, EVENT_ID_REQUIRE_TGT);
                }

            }
            return new Event(this, EVENT_ID_REQUIRE_MFA);
        }
        return new Event(this, EVENT_ID_REQUIRE_TGT);
    }
}
