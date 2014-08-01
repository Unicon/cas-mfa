package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.addons.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestResolver;
import net.unicon.cas.mfa.authentication.RequestedAuthenticationMethodRankingStrategy;
import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;

import net.unicon.cas.mfa.web.support.AuthenticationMethodVerifier;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.ticket.TicketException;
import org.jasig.cas.web.support.WebUtils;
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


    /**
     * Ctor.
     *
     * @param multiFactorAuthenticationRequestResolver multiFactorAuthenticationRequestResolver
     * @param authenticationSupport authenticationSupport
     * @param authenticationMethodVerifier authenticationMethodVerifier
     * @param authenticationMethodRankingStrategy authenticationMethodRankingStrategy
     */
    public TerminatingMultiFactorAuthenticationViaFormAction(
                                final MultiFactorAuthenticationRequestResolver multiFactorAuthenticationRequestResolver,
                                final AuthenticationSupport authenticationSupport,
                                final AuthenticationMethodVerifier authenticationMethodVerifier,
                                final RequestedAuthenticationMethodRankingStrategy authenticationMethodRankingStrategy) {

        super(multiFactorAuthenticationRequestResolver, authenticationSupport,
                authenticationMethodVerifier, authenticationMethodRankingStrategy);
    }

    /* {@inheritDoc} */
    @Override
    protected final Event multiFactorAuthenticationSuccessful(final Authentication authentication, final RequestContext context,
            final Credentials credentials, final MessageContext messageContext, final String id) throws TicketException {
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
     * @throws TicketException if the TGT cannot be created
     */
    private Event createTicketGrantingTicket(final Authentication authentication, final RequestContext context,
            final Credentials credentials, final MessageContext messageContext, final String id) throws TicketException  {

        final MultiFactorCredentials mfa = MultiFactorRequestContextUtils.getMfaCredentials(context);

        mfa.addAuthenticationToChain(authentication);
        mfa.getChainedCredentials().put(id, credentials);

        MultiFactorRequestContextUtils.setMfaCredentials(context, mfa);

        final String tgt = this.cas.createTicketGrantingTicket(mfa);
        WebUtils.putTicketGrantingTicketInRequestScope(context, tgt);
            return getSuccessEvent(context);
 
    }


    /* {@inheritDoc} */
    @Override
    protected final Event doAuthentication(final RequestContext context, final Credentials credentials,
            final MessageContext messageContext, final String id) throws Exception {
        return super.getErrorEvent();
    }
}
