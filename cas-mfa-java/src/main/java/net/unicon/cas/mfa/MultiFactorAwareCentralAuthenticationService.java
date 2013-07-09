package net.unicon.cas.mfa;

import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;

import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.ticket.ExpirationPolicy;
import org.jasig.cas.ticket.TicketException;
import org.jasig.cas.ticket.TicketGrantingTicket;
import org.jasig.cas.ticket.TicketGrantingTicketImpl;
import org.jasig.cas.ticket.registry.TicketRegistry;
import org.jasig.cas.util.UniqueTicketIdGenerator;
import org.jasig.cas.validation.Assertion;

/**
 * An extension of {@link CentralAuthenticationService} that routes CAS requests to a delegate,
 * thereby allowing the ability to partially override behavior that is MFA specific.
 * The current implementation is specific on the operation of creating ticket creating tickets
 * based on the assumptions that the credentials received are of type {@link MultiFactorCredentials}
 * and that the authentication context is verified and readily available, based on which the TGT will
 * be added to the configured {@link TicketRegistry}.
 *
 * This implementation here is merely responsible for creating the ticket granting ticket
 * and again, assumes that the authentication context has been established by all other
 * authentication managers in the flow. The authentication context is carried within the
 * {@link MultiFactorCredentials} instance.
 * @author Misagh Moayyed
 */
public final class MultiFactorAwareCentralAuthenticationService implements CentralAuthenticationService {
    private CentralAuthenticationService delegate;

    private UniqueTicketIdGenerator ticketGrantingTicketUniqueTicketIdGenerator;
    private TicketRegistry ticketRegistry;
    private ExpirationPolicy ticketGrantingTicketExpirationPolicy;

    @Override
    public String createTicketGrantingTicket(final Credentials credentials) throws TicketException {
        final MultiFactorCredentials mfaCredentials = (MultiFactorCredentials) credentials;
        final Authentication authentication = mfaCredentials.getAuthentication();

        final TicketGrantingTicket ticketGrantingTicket = new TicketGrantingTicketImpl(
                this.ticketGrantingTicketUniqueTicketIdGenerator.getNewTicketId(TicketGrantingTicket.PREFIX), authentication,
                this.ticketGrantingTicketExpirationPolicy);

        this.ticketRegistry.addTicket(ticketGrantingTicket);
        return ticketGrantingTicket.getId();
    }

    @Override
    public String grantServiceTicket(final String ticketGrantingTicketId, final Service service) throws TicketException {
        return this.delegate.grantServiceTicket(ticketGrantingTicketId, service);
    }

    @Override
    public String grantServiceTicket(final String ticketGrantingTicketId, final Service service, final Credentials credentials)
            throws TicketException {
        return this.delegate.grantServiceTicket(ticketGrantingTicketId, service, credentials);
    }

    @Override
    public Assertion validateServiceTicket(final String serviceTicketId, final Service service) throws TicketException {
        final Assertion assertion = this.delegate.validateServiceTicket(serviceTicketId, service);
        return assertion;
    }

    @Override
    public void destroyTicketGrantingTicket(final String ticketGrantingTicketId) {
        this.delegate.destroyTicketGrantingTicket(ticketGrantingTicketId);
    }

    @Override
    public String delegateTicketGrantingTicket(final String serviceTicketId, final Credentials credentials) throws TicketException {
        return this.delegate.delegateTicketGrantingTicket(serviceTicketId, credentials);
    }

    public void setTicketRegistry(final TicketRegistry ticketRegistry) {
        this.ticketRegistry = ticketRegistry;
    }

    public void setTicketGrantingTicketExpirationPolicy(final ExpirationPolicy ticketGrantingTicketExpirationPolicy) {
        this.ticketGrantingTicketExpirationPolicy = ticketGrantingTicketExpirationPolicy;
    }

    public void setTicketGrantingTicketUniqueTicketIdGenerator(final UniqueTicketIdGenerator uniqueTicketIdGenerator) {
        this.ticketGrantingTicketUniqueTicketIdGenerator = uniqueTicketIdGenerator;
    }

    public void setCentralAuthenticationServiceDelegate(final CentralAuthenticationService cas) {
        this.delegate = cas;
    }
}
