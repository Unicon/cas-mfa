package net.unicon.cas.mfa.web.flow;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;

import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;
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
import org.springframework.beans.factory.InitializingBean;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageContext;
import org.springframework.util.Assert;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * An abstraction that specifies how the authentication flow should behave.
 * It primarily acts as a wrapper recipient of authentication requests via form,
 * which is loosely mimics the behavior of {@link org.jasig.cas.web.flow.AuthenticationViaFormAction}.
 *
 * <p>Implementations are notified of the authentication type (MFA, non-MFA)
 * and are responsible to act accordingly.
 * @author Misagh Moayyed
 */
@SuppressWarnings("deprecation")
public abstract class AbstractMultiFactorAuthenticationViaFormAction implements InitializingBean {

    /** The Constant MFA_ERROR_EVENT_ID. */
    public static final String MFA_ERROR_EVENT_ID = "error";

    /** The Constant MFA_SUCCESS_EVENT_ID. */
    public static final String MFA_SUCCESS_EVENT_ID_PREFIX = "mfa_";

    /** The logger. */
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    /** The authentication manager. */
    @NotNull
    protected AuthenticationManager authenticationManager;

    /** The central authentication service. */
    @NotNull
    protected CentralAuthenticationService cas;

    /** The credentials binder. */
    @NotNull
    protected CredentialsBinder credentialsBinder;

    /**
     * Bind the request to the credentials.
     * @param context the context
     * @param credentials credentials
     * @throws Exception if the binding operation fails, or if the request cant be obtained
     */
    public final void doBind(final RequestContext context, final Credentials credentials) throws Exception {
        final HttpServletRequest request = WebUtils.getHttpServletRequest(context);

        if (this.credentialsBinder != null && this.credentialsBinder.supports(credentials.getClass())) {
            this.credentialsBinder.bind(request, credentials);
        }
    }

    /**
     * Determine whether the request is MFA compliant.
     * @param context the request context
     * @return true, if this is a MFA request.
     */
    private boolean isMultiFactorAuthenticationRequest(final RequestContext context) {
        final Service service = WebUtils.getService(context);
        return (service != null && service instanceof MultiFactorAuthenticationSupportingWebApplicationService);
    }

    /**
     * In the event of an MFA request, authenticate the credentials by default, and place
     * the authentication context back into the flow.
     *
     * @param context request context
     * @param credentials the requesting credentials
     * @param messageContext the message bundle manager
     * @param id the identifier of the credential, based on implementation provided in the flow setup.
     * @return the resulting event
     * @throws Exception the exception
     */
    protected final Event doMultiFactorAuthentication(final RequestContext context, final Credentials credentials,
            final MessageContext messageContext, final String id) throws Exception {

        Assert.notNull(id);
        Assert.notNull(credentials);

        try {
            final String tgt = WebUtils.getTicketGrantingTicketId(context);
            if (!StringUtils.isBlank(tgt)) {
                cas.destroyTicketGrantingTicket(tgt);
            }
            final Authentication auth = this.authenticationManager.authenticate(credentials);
            final Event result = multiFactorAuthenticationSuccessful(auth, context, credentials, messageContext, id);
            MultiFactorRequestContextUtils.setAuthentication(context, auth);
            return result;
        } catch (final AuthenticationException e) {
            logger.error(e.getMessage(), e);
        }
        return getErrorEvent();
    }


    /**
     * In the event of a non-MFA request, return the result of {@link #getErrorEvent()} by default.
     * Implementations are expected to override this method if they wish to respond to authentication
     * requests.
     *
     * @param context request context
     * @param credentials the requesting credentials
     * @param messageContext the message bundle manager
     * @return the resulting event
     * @throws Exception the exception
     */
    protected abstract Event doAuthentication(final RequestContext context, final Credentials credentials,
            final MessageContext messageContext) throws Exception;

    /**
     * Checks if is valid login ticket.
     *
     * @param context the context
     * @param messageContext the message context
     * @return true, if is valid login ticket
     */
    protected final boolean isValidLoginTicket(final RequestContext context, final MessageContext messageContext) {
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

    /**
     * Submit.
     *
     * @param context the context
     * @param credentials the credentials
     * @param messageContext the message context
     * @param id the id
     * @return the event
     * @throws Exception the exception
     */
    public final Event submit(final RequestContext context, final Credentials credentials, final MessageContext messageContext,
            final String id) throws Exception {

        if (isMultiFactorAuthenticationRequest(context)) {
            if (isValidLoginTicket(context, messageContext)) {
                return doMultiFactorAuthentication(context, credentials, messageContext, id);
            }
            return getErrorEvent();
        }
        return doAuthentication(context, credentials, messageContext);
    }

    /**
     * Multi factor authentication successful.
     *
     * @param authentication the authentication
     * @param context the context
     * @param credentials the credentials
     * @param messageContext the message context
     * @param id the id
     * @return the event
     */
    protected abstract Event multiFactorAuthenticationSuccessful(final Authentication authentication, final RequestContext context,
            final Credentials credentials, final MessageContext messageContext, final String id);

    /**
     * Set the binder instance.
     * @param credentialsBinder the binder instance
     */
    public final void setCredentialsBinder(@SuppressWarnings("hiding") final CredentialsBinder credentialsBinder) {
        this.credentialsBinder = credentialsBinder;
    }

    /**
     * CAS instance used to handle authentications. This CAS instance is only
     * effective when the incoming service does not specify a valid loa.
     * @param centralAuthenticationService the cas instance.
     */
    public final void setCentralAuthenticationService(final CentralAuthenticationService centralAuthenticationService) {
        this.cas = centralAuthenticationService;
    }

    /**
     * Authentication manager instance to authenticate the user by its configured
     * handlers as the first leg of an multifactor authentication sequence.
     *
     * @param manager the new multi factor authentication manager
     */
    public final void setMultiFactorAuthenticationManager(final AuthenticationManager manager) {
        this.authenticationManager = manager;
    }

    /**
     * The webflow error event id.
     * @return error event id
     */
    protected final Event getErrorEvent() {
        return new Event(this, MFA_ERROR_EVENT_ID);
    }

    /**
     * Return the mfa webflow id.
     * @return the webflow id
     */
    protected final Event getSuccessEvent(final RequestContext context) {
        final MultiFactorAuthenticationSupportingWebApplicationService service = (MultiFactorAuthenticationSupportingWebApplicationService)
                WebUtils.getService(context);
        return new Event(this, MFA_SUCCESS_EVENT_ID_PREFIX + service.getAuthenticationMethod());
    }

    /* (non-Javadoc)
     * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
     */
    @Override
    public void afterPropertiesSet() throws Exception {
    }
}
