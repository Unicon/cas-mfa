package net.unicon.cas.mfa.web.flow;

import java.io.Serializable;

/**
 *
 * @author Misagh Moayyed
 */
public interface MultiFactorAuthenticationConstants extends Serializable {
    String CAS_AUTHENTICATION_ATTR_NAME = "casAuthentication";

    String CAS_TICKET_GRANTING_TICKET_ATTR_NAME = "ticketGrantingTicketId";
}
