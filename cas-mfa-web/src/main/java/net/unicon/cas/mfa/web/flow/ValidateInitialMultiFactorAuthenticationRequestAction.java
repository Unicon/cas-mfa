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
 * Attempts to validate an incoming multifactor authentication request. If the incoming
 * service is an instance of {@link MultiFactorAuthenticationSupportingWebApplicationService}
 * then the following validation rules are activated:
 *
 * <p>
 * <ol>
 *  <li>If an authentication context does not exist, proceed to #4.</li>
 *  <li>If an authentication context exists without any MFA decorations, require MFA.</li>
 *  <li>If an authentication context provided by MFA exists, yet the authentication method does not
 *  match that of requested, require MFA.</li>
 *  <li>Otherwise, proceed to require/verify the existence of the TGT as usual.</li>
 * </ol>
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
