package net.unicon.cas.mfa;

import com.codahale.metrics.annotation.Counted;
import com.codahale.metrics.annotation.Metered;
import com.codahale.metrics.annotation.Timed;
import com.google.common.base.Predicate;
import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;
import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationManager;
import org.jasig.cas.authentication.Credential;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.logout.LogoutRequest;
import org.jasig.cas.ticket.ExpirationPolicy;
import org.jasig.cas.ticket.InvalidTicketException;
import org.jasig.cas.ticket.ServiceTicket;
import org.jasig.cas.ticket.Ticket;
import org.jasig.cas.ticket.TicketCreationException;
import org.jasig.cas.ticket.TicketException;
import org.jasig.cas.ticket.TicketGrantingTicket;
import org.jasig.cas.ticket.TicketGrantingTicketImpl;
import org.jasig.cas.ticket.registry.TicketRegistry;
import org.jasig.cas.util.UniqueTicketIdGenerator;
import org.jasig.cas.validation.Assertion;
import org.jasig.inspektr.audit.annotation.Audit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.constraints.NotNull;
import java.util.Collection;
import java.util.List;

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

    /** Log instance for logging events, info, warnings, errors, etc. */
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    /** The wrapped CentralAuthenticationService. */
    private CentralAuthenticationService delegate;

    private UniqueTicketIdGenerator ticketGrantingTicketUniqueTicketIdGenerator;

    private TicketRegistry ticketRegistry;

    private ExpirationPolicy ticketGrantingTicketExpirationPolicy;

    private AuthenticationManager authenticationManager;

    /** New Ticket Registry for storing and retrieving services tickets. Can point to the same one as the ticketRegistry variable. */
    @NotNull
    private TicketRegistry serviceTicketRegistry;

    @Override
    @Audit(
            action="TICKET_GRANTING_TICKET",
            actionResolverName="CREATE_TICKET_GRANTING_TICKET_RESOLVER",
            resourceResolverName="CREATE_TICKET_GRANTING_TICKET_RESOURCE_RESOLVER")
    @Timed(name = "CREATE_TICKET_GRANTING_TICKET_TIMER")
    @Metered(name = "CREATE_TICKET_GRANTING_TICKET_METER")
    @Counted(name="CREATE_TICKET_GRANTING_TICKET_COUNTER", monotonic=true)
    public TicketGrantingTicket createTicketGrantingTicket(final Credential... credentials) throws TicketException {
        final MultiFactorCredentials mfaCredentials = (MultiFactorCredentials) credentials[0];
        final Authentication authentication = mfaCredentials.getAuthentication();

        if (authentication == null) {
            throw new TicketCreationException(new RuntimeException("Authentication cannot be null"));
        }
        final TicketGrantingTicket ticketGrantingTicket = new TicketGrantingTicketImpl(
                this.ticketGrantingTicketUniqueTicketIdGenerator.getNewTicketId(TicketGrantingTicket.PREFIX),
                authentication,
                this.ticketGrantingTicketExpirationPolicy);

        this.ticketRegistry.addTicket(ticketGrantingTicket);
        return ticketGrantingTicket;
    }

    @Timed(name = "GET_TICKET_TIMER")
    @Metered(name = "GET_TICKET_METER")
    @Counted(name="GET_TICKET_COUNTER", monotonic=true)
    @Override
    public <T extends Ticket> T getTicket(final String ticketId, final Class<? extends Ticket> clazz)
            throws InvalidTicketException {
        return delegate.getTicket(ticketId, clazz);

    }

    @Timed(name = "GET_TICKETS_TIMER")
    @Metered(name = "GET_TICKETS_METER")
    @Counted(name="GET_TICKETS_COUNTER", monotonic=true)
    @Override
    public Collection<Ticket> getTickets(final Predicate predicate) {
        return this.delegate.getTickets(predicate);
    }

    @Audit(
            action="SERVICE_TICKET",
            actionResolverName="GRANT_SERVICE_TICKET_RESOLVER",
            resourceResolverName="GRANT_SERVICE_TICKET_RESOURCE_RESOLVER")
    @Timed(name = "GRANT_SERVICE_TICKET_TIMER")
    @Metered(name="GRANT_SERVICE_TICKET_METER")
    @Counted(name="GRANT_SERVICE_TICKET_COUNTER", monotonic=true)
    @Override
    public ServiceTicket grantServiceTicket(final String ticketGrantingTicketId,
                                            final Service service) throws TicketException {
        return this.delegate.grantServiceTicket(ticketGrantingTicketId, service);
    }


    @Audit(
            action="SERVICE_TICKET",
            actionResolverName="GRANT_SERVICE_TICKET_RESOLVER",
            resourceResolverName="GRANT_SERVICE_TICKET_RESOURCE_RESOLVER")
    @Timed(name="GRANT_SERVICE_TICKET_TIMER")
    @Metered(name="GRANT_SERVICE_TICKET_METER")
    @Counted(name="GRANT_SERVICE_TICKET_COUNTER", monotonic=true)
    @Override
    public ServiceTicket grantServiceTicket(
            final String ticketGrantingTicketId,
            final Service service, final Credential... credentials)
            throws org.jasig.cas.authentication.AuthenticationException, TicketException {
        return this.delegate.grantServiceTicket(ticketGrantingTicketId, service, credentials);
    }

    @Audit(
            action="SERVICE_TICKET_VALIDATE",
            actionResolverName="VALIDATE_SERVICE_TICKET_RESOLVER",
            resourceResolverName="VALIDATE_SERVICE_TICKET_RESOURCE_RESOLVER")
    @Timed(name="VALIDATE_SERVICE_TICKET_TIMER")
    @Metered(name="VALIDATE_SERVICE_TICKET_METER")
    @Counted(name="VALIDATE_SERVICE_TICKET_COUNTER", monotonic=true)
    @Override
    public Assertion validateServiceTicket(final String serviceTicketId, final Service service) throws TicketException {
        return this.delegate.validateServiceTicket(serviceTicketId, service);
    }

    @Audit(
            action="TICKET_GRANTING_TICKET_DESTROYED",
            actionResolverName="DESTROY_TICKET_GRANTING_TICKET_RESOLVER",
            resourceResolverName="DESTROY_TICKET_GRANTING_TICKET_RESOURCE_RESOLVER")
    @Timed(name = "DESTROY_TICKET_GRANTING_TICKET_TIMER")
    @Metered(name="DESTROY_TICKET_GRANTING_TICKET_METER")
    @Counted(name="DESTROY_TICKET_GRANTING_TICKET_COUNTER", monotonic=true)
    @Override
    public List<LogoutRequest> destroyTicketGrantingTicket(@NotNull final String ticketGrantingTicketId) {
        return this.delegate.destroyTicketGrantingTicket(ticketGrantingTicketId);
    }

    @Audit(
            action="PROXY_GRANTING_TICKET",
            actionResolverName="GRANT_PROXY_GRANTING_TICKET_RESOLVER",
            resourceResolverName="GRANT_PROXY_GRANTING_TICKET_RESOURCE_RESOLVER")
    @Timed(name="GRANT_PROXY_GRANTING_TICKET_TIMER")
    @Metered(name="GRANT_PROXY_GRANTING_TICKET_METER")
    @Counted(name="GRANT_PROXY_GRANTING_TICKET_COUNTER", monotonic=true)
    @Override
    public TicketGrantingTicket delegateTicketGrantingTicket(final String serviceTicketId, final Credential... credentials)
            throws org.jasig.cas.authentication.AuthenticationException, TicketException {
        return this.delegate.delegateTicketGrantingTicket(serviceTicketId, credentials);
    }

    public void setAuthenticationManager(final AuthenticationManager manager) {
        this.authenticationManager = manager;
    }

    /**
     * The set TicketRegistry should be the same registry used by the CentralAuthenticationService instance
     * provided to setCentralAuthenticationServiceDelegate.
     * @param ticketRegistry non-null TicketRegistry shared with the delegate CAS
     */
    /**
     * Method to set the TicketRegistry.
     *
     * @param ticketRegistry the TicketRegistry to set.
     */
    public void setTicketRegistry(final TicketRegistry ticketRegistry) {
        this.ticketRegistry = ticketRegistry;

        if (this.serviceTicketRegistry == null) {
            this.serviceTicketRegistry = ticketRegistry;
        }
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
