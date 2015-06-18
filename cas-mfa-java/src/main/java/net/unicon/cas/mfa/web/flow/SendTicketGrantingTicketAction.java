package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.addons.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;
import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.web.support.CookieRetrievingCookieGenerator;
import org.jasig.cas.web.support.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.validation.constraints.NotNull;

/**
 * This is {@link SendTicketGrantingTicketAction} that mimics the default component in CAS
 * with one key difference: it will only destroy the previous TGT issued if there is no MFA
 * context available.
 *
 * If a TGT is issued as part of primary authn first without without going through MFA,
 * that TGT will remain in the context. Subsequent requests that are MFA-aware will create
 * new MFA-aware TGTs with their associated authentications. But, we will not be able to kill
 * the previous TGT because that may have cached the credentials as part of the original primary authn
 * and invalidating it will cause issues for extensions such as clearPass.
 *
 * The default behavior is that of CAS which assumes to caching of principal credential.
 * Deployments that require that type of caching will need to disable destroying the primary authn TGT
 * via {@link #setDestroyPreviousSSOSession(boolean)}.
 *
 * @author Misagh Moayyed
 */
public final class SendTicketGrantingTicketAction extends org.springframework.webflow.action.AbstractAction {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @NotNull
    private CookieRetrievingCookieGenerator ticketGrantingTicketCookieGenerator;

    /** Instance of CentralAuthenticationService. */
    @NotNull
    private CentralAuthenticationService centralAuthenticationService;

    private AuthenticationSupport authenticationSupport;

    private boolean destroyPreviousSSOSession = true;

    @Override
    protected Event doExecute(final RequestContext context) {

        final MultiFactorCredentials mfa = MultiFactorRequestContextUtils.getMfaCredentials(context);

        final String ticketGrantingTicketId = WebUtils.getTicketGrantingTicketId(context);
        final String ticketGrantingTicketValueFromCookie = (String) context.getFlowScope().get("ticketGrantingTicketId");

        if (ticketGrantingTicketId == null) {
            return success();
        }

        this.ticketGrantingTicketCookieGenerator.addCookie(WebUtils.getHttpServletRequest(context), WebUtils
                .getHttpServletResponse(context), ticketGrantingTicketId);

        if ((mfa == null || this.destroyPreviousSSOSession)
                && ticketGrantingTicketValueFromCookie != null
                && !ticketGrantingTicketId.equals(ticketGrantingTicketValueFromCookie)) {
            logger.debug("Destroying the previous SSO session mapped to [{}] because, this is not an MFA request,"
                    + " or configuration dictated destroying the SSO session.", ticketGrantingTicketValueFromCookie);
            this.centralAuthenticationService.destroyTicketGrantingTicket(ticketGrantingTicketValueFromCookie);
        }

        return success();
    }

    public void setTicketGrantingTicketCookieGenerator(final CookieRetrievingCookieGenerator ticketGrantingTicketCookieGenerator) {
        this.ticketGrantingTicketCookieGenerator= ticketGrantingTicketCookieGenerator;
    }

    public void setCentralAuthenticationService(
            final CentralAuthenticationService centralAuthenticationService) {
        this.centralAuthenticationService = centralAuthenticationService;
    }

    public void setAuthenticationSupport(final AuthenticationSupport authenticationSupport) {
        this.authenticationSupport = authenticationSupport;
    }

    public void setDestroyPreviousSSOSession(final boolean destroyPreviousSSOSession) {
        this.destroyPreviousSSOSession = destroyPreviousSSOSession;
    }
}
