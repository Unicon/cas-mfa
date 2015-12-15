package net.unicon.cas.addons.authentication;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.ticket.TicketGrantingTicket;
import org.jasig.cas.ticket.registry.TicketRegistry;

import java.util.Map;

/**
 * Default implementation of <code>AuthenticationSupport</code>.
 * <p/>
 * Uses CAS' <code>TicketRegistry</code> to retrieve TGT and its associated objects by provided tgt String token
 *
 * @author Dmitriy Kopylenko
 * @author Unicon, inc.
 */
public class DefaultAuthenticationSupport implements AuthenticationSupport {

    private TicketRegistry ticketRegistry;

    public DefaultAuthenticationSupport(final TicketRegistry ticketRegistry) {
        this.ticketRegistry = ticketRegistry;
    }

    @Override
    /** {@inheritDoc} */
    public Authentication getAuthenticationFrom(final String ticketGrantingTicketId) throws RuntimeException {
        final TicketGrantingTicket tgt = (TicketGrantingTicket) this.ticketRegistry.getTicket(ticketGrantingTicketId, TicketGrantingTicket.class);
        return tgt == null ? null : tgt.getAuthentication();
    }

    @Override
    /** {@inheritDoc} */
    public Principal getAuthenticatedPrincipalFrom(final String ticketGrantingTicketId) throws RuntimeException {
        final Authentication auth = getAuthenticationFrom(ticketGrantingTicketId);
        return auth == null ? null : auth.getPrincipal();
    }

    @Override
    /** {@inheritDoc} */
    public Map<String, Object> getPrincipalAttributesFrom(final String ticketGrantingTicketId) throws RuntimeException {
        final Principal principal = getAuthenticatedPrincipalFrom(ticketGrantingTicketId);
        return principal == null ? null : principal.getAttributes();
    }
}
