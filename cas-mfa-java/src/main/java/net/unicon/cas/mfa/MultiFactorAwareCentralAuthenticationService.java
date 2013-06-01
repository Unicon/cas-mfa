package net.unicon.cas.mfa;

import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;

import org.jasig.cas.CentralAuthenticationService;
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
 *
 * @author Misagh Moayyed
 *
 */
public final class MultiFactorAwareCentralAuthenticationService implements CentralAuthenticationService {
    private CentralAuthenticationService delegate;

    private UniqueTicketIdGenerator ticketGrantingTicketUniqueTicketIdGenerator;
    private TicketRegistry ticketRegistry;
    private ExpirationPolicy ticketGrantingTicketExpirationPolicy;

    @Override
    public String createTicketGrantingTicket(final Credentials credentials) throws TicketException {
        final MultiFactorCredentials mfaCredentials = (MultiFactorCredentials) credentials;
        final TicketGrantingTicket ticketGrantingTicket = new TicketGrantingTicketImpl(
                this.ticketGrantingTicketUniqueTicketIdGenerator.getNewTicketId(TicketGrantingTicket.PREFIX),
                mfaCredentials.getAuthentication(), this.ticketGrantingTicketExpirationPolicy);

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
        return this.delegate.validateServiceTicket(serviceTicketId, service);
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
