package net.unicon.cas.mfa.web.flow;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationManager;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.web.bind.CredentialsBinder;
import org.jasig.cas.web.support.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 *
 * @author Misagh Moayyed
 *
 */
@SuppressWarnings("deprecation")
public abstract class AbstractMultiFactorAuthenticationViaFormAction {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    @NotNull
    protected AuthenticationManager authenticationManager;

    @NotNull
    protected CentralAuthenticationService centralAuthenticationService;

    @NotNull
    protected CredentialsBinder credentialsBinder;

    /**
     * Bind the request to the credentials.
     * @param context the context
     * @param credentials credentials
     */
    public void doBind(final RequestContext context, final Credentials credentials) throws Exception {
        final HttpServletRequest request = WebUtils.getHttpServletRequest(context);

        if (this.credentialsBinder != null && this.credentialsBinder.supports(credentials.getClass())) {
            this.credentialsBinder.bind(request, credentials);
        }
    }

    protected boolean isMultiFactorAuthenticationRequest(final RequestContext context) {
        final Service service = WebUtils.getService(context);
        return (service != null && service instanceof MultiFactorAuthenticationSupportingWebApplicationService);
    }

    protected final Event doMultiFactorAuthentication(final RequestContext context, final Credentials credentials,
            final MessageContext messageContext, final String id) throws Exception {
        try {
            final String tgt = WebUtils.getTicketGrantingTicketId(context);
            if (!StringUtils.isBlank(tgt)) {
                centralAuthenticationService.destroyTicketGrantingTicket(tgt);
            }
            final Authentication auth = this.authenticationManager.authenticate(credentials);

            context.getFlowScope().put(MultiFactorAuthenticationConstants.CAS_AUTHENTICATION_ATTR_NAME, auth);
            return multiFactorAuthenticationSuccessful(auth, context, credentials, messageContext, id);
        } catch (final AuthenticationException e) {
            logger.error(e.getMessage(), e);
        }
        return getErrorEvent();
    }

    protected Event doAuthentication(final RequestContext context, final Credentials credentials, final MessageContext messageContext)
            throws Exception {
        return getErrorEvent();
    }

    protected boolean validateLoginTicket(final RequestContext context, final MessageContext messageContext) {
        final String authoritativeLoginTicket = WebUtils.getLoginTicketFromFlowScope(context);
        final String providedLoginTicket = WebUtils.getLoginTicketFromRequest(context);
        if (!authoritativeLoginTicket.equals(providedLoginTicket)) {
            logger.warn("Invalid login ticket {}", providedLoginTicket);
            final String code = "INVALID_TICKET";
            messageContext.addMessage(new MessageBuilder().error().code(code).arg(providedLoginTicket).defaultText(code).build());
            return false;
        }
        return true;
    }

    public Event submit(final RequestContext context, final Credentials credentials, final MessageContext messageContext, final String id)
            throws Exception {

        if (validateLoginTicket(context, messageContext)) {
            if (isMultiFactorAuthenticationRequest(context)) {
                return doMultiFactorAuthentication(context, credentials, messageContext, id);
            }
            return doAuthentication(context, credentials, messageContext);
        }

        return getErrorEvent();
    }

    protected Event multiFactorAuthenticationSuccessful(final Authentication authentication, final RequestContext context,
            final Credentials credentials, final MessageContext messageContext, final String id) {
        return getSuccessEvent();
    }

    /**
     * Set the binder instance.
     * @param credentialsBinder the binder instance
     */
    public void setCredentialsBinder(final CredentialsBinder credentialsBinder) {
        this.credentialsBinder = credentialsBinder;
    }

    /**
     * CAS instance used to handle authentications. This CAS instance is only
     * effective when the incoming service does not specify a valid loa.
     * @param centralAuthenticationService the cas instance.
     */
    public void setCentralAuthenticationService(final CentralAuthenticationService centralAuthenticationService) {
        this.centralAuthenticationService = centralAuthenticationService;
    }

    /**
     * Authentication manager instance to authenticate the user by its configured
     * handlers as the first leg of an multifactor authentication sequence.
     * @param manager
     */
    public void setMultiFactorAuthenticationManager(final AuthenticationManager manager) {
        this.authenticationManager = manager;
    }

    /**
     * The webflow error event id.
     * @return error event id
     */
    protected Event getErrorEvent() {
        return new Event(this, "error");
    }

    /**
     * Return the mfa webflow id.
     * @return the webflow id
     */
    protected Event getSuccessEvent() {
        return new Event(this, "mfaSuccess");
    }
}
