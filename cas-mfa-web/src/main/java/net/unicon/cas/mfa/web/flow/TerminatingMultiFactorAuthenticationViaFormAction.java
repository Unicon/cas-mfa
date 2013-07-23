package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.ticket.TicketException;
import org.jasig.cas.web.support.WebUtils;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * This is the final webflow action in the mfa authentication sequence that
 * would ultimately issue the TGT and presents the "success" event. If multiple
 * actions are chained during the authentication sequence, this should be the last.
 * @author Misagh Moayyed
 */
public class TerminatingMultiFactorAuthenticationViaFormAction extends AbstractMultiFactorAuthenticationViaFormAction {

    /* {@inheritDoc} */
    @Override
    protected final Event multiFactorAuthenticationSuccessful(final Authentication authentication, final RequestContext context,
            final Credentials credentials, final MessageContext messageContext, final String id) {

        return createTicketGrantingTicket(authentication, context, credentials, messageContext, id);
    }

    /**
     * Creates the ticket granting ticket.
     *
     * @param authentication the authentication
     * @param context the context
     * @param credentials the credentials
     * @param messageContext the message context
     * @param id the id
     * @return the event
     */
    private Event createTicketGrantingTicket(final Authentication authentication, final RequestContext context,
            final Credentials credentials, final MessageContext messageContext, final String id) {
        try {
            final MultiFactorCredentials mfa = MultiFactorRequestContextUtils.getMfaCredentials(context);

            mfa.getChainedAuthentications().add(authentication);
            mfa.getChainedCredentials().put(id, credentials);

            MultiFactorRequestContextUtils.setMfaCredentials(context, mfa);

            final String tgt = this.cas.createTicketGrantingTicket(mfa);
            WebUtils.putTicketGrantingTicketInRequestScope(context, tgt);
            return getSuccessEvent();
        } catch (final TicketException e) {
            populateErrorsInstance(e, messageContext);
            logger.error(e.getMessage(), e);
            return getErrorEvent();
        }
    }

    /**
     * Populate errors instance.
     *
     * @param e the e
     * @param messageContext the message context
     */
    private void populateErrorsInstance(final TicketException e, final MessageContext messageContext) {
        try {
            messageContext.addMessage(new MessageBuilder().error().code(e.getCode()).defaultText(e.getCode()).build());
        } catch (final Exception fe) {
            logger.error(fe.getMessage(), fe);
        }
    }

    /* {@inheritDoc} */
    @Override
    protected final Event doAuthentication(final RequestContext context, final Credentials credentials,
            final MessageContext messageContext) throws Exception {
        return super.getErrorEvent();
    }
}
