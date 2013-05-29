package net.unicon.cas.mfa.web.flow;

import javax.validation.constraints.NotNull;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationService;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationManager;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.web.bind.CredentialsBinder;
import org.jasig.cas.web.flow.AuthenticationViaFormAction;
import org.jasig.cas.web.support.WebUtils;
import org.springframework.binding.message.MessageContext;
import org.springframework.web.util.CookieGenerator;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * The multifactor authentication service action that branches to an loa-defined
 * subflow state based on the service loa requirement. If the requesting service
 * is an instance of {@link MultiFactorAuthenticationService}, this action would simply
 * attempt to verify the given credentials based on {@link #setAuthenticationManager(AuthenticationManager)}
 * and will alter the webflow to the next leg of the authentication sequence.
 * @author Misagh Moayyed
 */
@SuppressWarnings("deprecation")
public class MultiFactorAuthenticationViaFormAction {

    private final AuthenticationViaFormAction wrapperAuthenticationAction = new AuthenticationViaFormAction();

    @NotNull
    private AuthenticationManager authenticationManager;

    private CentralAuthenticationService centralAuthenticationService;

    /**
     * Bind the request to the credentials.
     * @param context the context
     * @param credentials credentials
     * @throws Exception in case of bind failures
     */
    public final void doBind(final RequestContext context, final Credentials credentials) throws Exception {
        wrapperAuthenticationAction.doBind(context, credentials);
    }

    public final String submit(final RequestContext context, final Credentials credentials, final MessageContext messageContext)
            throws Exception {

        final Service service = WebUtils.getService(context);

        if (service != null && service instanceof MultiFactorAuthenticationService) {
            try {
                final String tgt = WebUtils.getTicketGrantingTicketId(context);
                if (!StringUtils.isBlank(tgt)) {
                    centralAuthenticationService.destroyTicketGrantingTicket(tgt);
                }
                final Authentication auth = this.authenticationManager.authenticate(credentials);
                if (auth != null) {
                    return getMfaEvent().getId();
                }
            } catch (final AuthenticationException e) {
                return getErrorEvent().getId();
            }
        } else {
            final Event event = new Event(this, wrapperAuthenticationAction.submit(context, credentials, messageContext));
            return event.getId();
        }
        return getErrorEvent().getId();
    }

    /**
     * The webflow error event id.
     * @return error event id
     */
    protected final Event getErrorEvent() {
        return new Event(this, "error");
    }

    /**
     * Return the mfa webflow id.
     * @return the webflow id
     */
    protected final Event getMfaEvent() {
        return new Event(this, "mfa");
    }

    /**
     * Set the binder instance.
     * @param credentialsBinder the binder instance
     */
    public final void setCredentialsBinder(final CredentialsBinder credentialsBinder) {
        wrapperAuthenticationAction.setCredentialsBinder(credentialsBinder);
    }

    /**
     * The cookie generator to keep track of "warn" state.
     * @param warnCookieGenerator the generator.
     */
    public final void setWarnCookieGenerator(final CookieGenerator warnCookieGenerator) {
        wrapperAuthenticationAction.setWarnCookieGenerator(warnCookieGenerator);
    }

    /**
     * CAS instance used to handle authentications. This CAS instance is only
     * effective when the incoming service does not specify a valid loa.
     * @param centralAuthenticationService the cas instance.
     */
    public final void setCentralAuthenticationService(final CentralAuthenticationService centralAuthenticationService) {
        wrapperAuthenticationAction.setCentralAuthenticationService(centralAuthenticationService);
        this.centralAuthenticationService = centralAuthenticationService;
    }

    /**
     * Authentication manager instance to authenticate the user by its configured
     * handlers as the first leg of an multifactor authentication sequence.
     * @param manager
     */
    public final void setAuthenticationManager(final AuthenticationManager manager) {
        this.authenticationManager = manager;
    }
}
