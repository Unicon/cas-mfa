package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;

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
 * would ultimate issue the TGT and presents the "success" event. If multiple
 * actions are chained during the authentication sequence, this should be the last.
 * @author Misagh Moayyed
 */
public class TerminatingMultiFactorAuthenticationViaFormAction extends AbstractMultiFactorAuthenticationViaFormAction {

    @Override
    protected Event multiFactorAuthenticationSuccessful(final Authentication authentication, final RequestContext context,
            final Credentials credentials, final MessageContext messageContext, final String id) {

        return createTicketGrantingTicket(authentication, context, credentials, messageContext, id);
    }

    private Event createTicketGrantingTicket(final Authentication authentication, final RequestContext context,
            final Credentials credentials, final MessageContext messageContext, final String id) {
        try {

            final MultiFactorCredentials mfa = (MultiFactorCredentials) context.getFlowScope().get("mfaCredentials",
                    MultiFactorCredentials.class);

            mfa.getChainedAuthentication().add(authentication);
            mfa.getChainedCredentials().put(id, credentials);

            context.getFlowScope().put("mfaCredentials", mfa);
            WebUtils.putTicketGrantingTicketInRequestScope(context,
                    this.centralAuthenticationService.createTicketGrantingTicket(mfa));
            return getSuccessEvent();
        } catch (final TicketException e) {
            populateErrorsInstance(e, messageContext);
            logger.error(e.getMessage(), e);
            return getErrorEvent();
        }
    }

    private void populateErrorsInstance(final TicketException e, final MessageContext messageContext) {
        try {
            messageContext.addMessage(new MessageBuilder().error().code(e.getCode()).defaultText(e.getCode()).build());
        } catch (final Exception fe) {
            logger.error(fe.getMessage(), fe);
        }
    }
}
