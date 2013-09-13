package net.unicon.cas.mfa;

import com.github.inspektr.audit.annotation.Audit;
import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;

import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationManager;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.ticket.ExpirationPolicy;
import org.jasig.cas.ticket.ServiceTicket;
import org.jasig.cas.ticket.TicketCreationException;
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
 *
 * Assumptions: the TicketRegistry wired into this CentralAuthenticationService instance is the same as that wired
 * into the wrapped delegate.
 * (That way when this implementation adds tickets directly to the registry in createTGT and delegateTGT
 * those tickets will be available to the delegate in its fulfilling such methods as grantServiceTicket.)
 *
 *
 * @author Misagh Moayyed
 */
public final class MultiFactorAwareCentralAuthenticationService implements CentralAuthenticationService {


    /**
     * The wrapped CentralAuthenticationService.
     */
    private CentralAuthenticationService delegate;

    private UniqueTicketIdGenerator ticketGrantingTicketUniqueTicketIdGenerator;
    private TicketRegistry ticketRegistry;
    private ExpirationPolicy ticketGrantingTicketExpirationPolicy;

    private AuthenticationManager authenticationManager;

    @Override
    @Audit(
            action="TICKET_GRANTING_TICKET",
            actionResolverName="CREATE_TICKET_GRANTING_TICKET_RESOLVER",
            resourceResolverName="CREATE_TICKET_GRANTING_TICKET_RESOURCE_RESOLVER")
    public String createTicketGrantingTicket(final Credentials credentials) throws TicketException {
        final MultiFactorCredentials mfaCredentials = (MultiFactorCredentials) credentials;
        final Authentication authentication = mfaCredentials.getAuthentication();

        final TicketGrantingTicket ticketGrantingTicket = new TicketGrantingTicketImpl(
                this.ticketGrantingTicketUniqueTicketIdGenerator.getNewTicketId(TicketGrantingTicket.PREFIX), authentication,
                this.ticketGrantingTicketExpirationPolicy);

        this.ticketRegistry.addTicket(ticketGrantingTicket);
        return ticketGrantingTicket.getId();
    }

    /*
     * Implements Audit Trail participation by virtue of the delegate's audit trail participation.
     */
    @Override
    public String grantServiceTicket(final String ticketGrantingTicketId, final Service service) throws TicketException {
        return this.delegate.grantServiceTicket(ticketGrantingTicketId, service);
    }

    /*
     * Implements Audit Trail participation by virtue of the delegate's audit trail participation.
     */
    @Override
    public String grantServiceTicket(final String ticketGrantingTicketId, final Service service, final Credentials credentials)
            throws TicketException {
        return this.delegate.grantServiceTicket(ticketGrantingTicketId, service, credentials);
    }

    /*
     * Implements Audit Trail participation by virtue of the delegate's audit trail participation.
     */
    @Override
    public Assertion validateServiceTicket(final String serviceTicketId, final Service service) throws TicketException {
        return this.delegate.validateServiceTicket(serviceTicketId, service);
    }

    /*
     * Implements Audit Trail participation by virtue of the delegate's audit trail participation.
     */
    @Override
    public void destroyTicketGrantingTicket(final String ticketGrantingTicketId) {
        this.delegate.destroyTicketGrantingTicket(ticketGrantingTicketId);
    }

    @Override
    public String delegateTicketGrantingTicket(final String serviceTicketId, final Credentials credentials) throws TicketException {
        try {
            this.authenticationManager.authenticate(credentials);
            final ServiceTicket serviceTicket = (ServiceTicket) this.ticketRegistry.getTicket(serviceTicketId, ServiceTicket.class);
            final TicketGrantingTicket tgt = serviceTicket.getGrantingTicket();

            final MultiFactorCredentials mfaCredentials = new MultiFactorCredentials();
            mfaCredentials.addAuthenticationToChain(tgt.getAuthentication());

            final Authentication authentication = mfaCredentials.getAuthentication();
            final TicketGrantingTicket ticketGrantingTicket = serviceTicket.grantTicketGrantingTicket(
                    this.ticketGrantingTicketUniqueTicketIdGenerator.getNewTicketId(TicketGrantingTicket.PREFIX),
                    authentication, this.ticketGrantingTicketExpirationPolicy);

            this.ticketRegistry.addTicket(ticketGrantingTicket);

            return ticketGrantingTicket.getId();
        } catch (final AuthenticationException e) {
            throw new TicketCreationException(e);
        }
    }

    public void setAuthenticationManager(final AuthenticationManager manager) {
        this.authenticationManager = manager;
    }

    /**
     * The set TicketRegistry should be the same registry used by the CentralAuthenticationService instance
     * provided to setCentralAuthenticationServiceDelegate.
     * @param ticketRegistry non-null TicketRegistry shared with the delegate CAS
     */
    public void setTicketRegistry(final TicketRegistry ticketRegistry) {
        this.ticketRegistry = ticketRegistry;
    }

    /**
     * Inject a ticket granting ticket expiration policy.
     * @param ticketGrantingTicketExpirationPolicy the non-null policy on TGT expiration.
     */
    public void setTicketGrantingTicketExpirationPolicy(final ExpirationPolicy ticketGrantingTicketExpirationPolicy) {
        this.ticketGrantingTicketExpirationPolicy = ticketGrantingTicketExpirationPolicy;
    }

    /**
     * Inject a TGT unique ID generator.
     * @param uniqueTicketIdGenerator the non-null TGT unique ID generator.
     */
    public void setTicketGrantingTicketUniqueTicketIdGenerator(final UniqueTicketIdGenerator uniqueTicketIdGenerator) {
        this.ticketGrantingTicketUniqueTicketIdGenerator = uniqueTicketIdGenerator;
    }

    /**
     * Inject a delegate CAS implementation to fulfill the non-TGT-creating CAS API methods.
     * The delegate CAS instance should share a TicketRegistry with this CAS instance otherwise this CAS will be
     * granting TGTs that will not be honored by the delegate.
     * @param cas the non-null delegate CAS
     */
    public void setCentralAuthenticationServiceDelegate(final CentralAuthenticationService cas) {
        this.delegate = cas;
    }
}
