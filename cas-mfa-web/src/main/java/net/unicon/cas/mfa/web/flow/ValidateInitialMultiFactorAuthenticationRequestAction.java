package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.addons.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.web.support.WebUtils;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * Attempts to validate an incoming multifactor authentication request. If the incoming
 * service is an instance of {@link MultiFactorAuthenticationSupportingWebApplicationService}
 * and there exists a valid TGT from which an {@link org.jasig.cas.authentication.Authentication} context can be gleaned,
 * the MFA request is considered "valid". Otherwise, "invalid".
 * @author Misagh Moayyed
 */
public final class ValidateInitialMultiFactorAuthenticationRequestAction extends AbstractAction {

    /** The Constant EVENT_ID_VALID. */
    public static final String EVENT_ID_VALID = "valid";

    /** The Constant EVENT_ID_INVALID. */
    public static final String EVENT_ID_INVALID = "invalid";

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
            if (this.authenticationSupport.getAuthenticationFrom(tgt) != null) {
                return new Event(this, EVENT_ID_VALID);
            }
        }
        return new Event(this, EVENT_ID_INVALID);
    }
}
