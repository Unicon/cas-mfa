package net.unicon.cas.mfa.web.flow;

import java.io.Serializable;

/**
 * An empty-bodies interface whose sole purpose is to be a home to
 * MFA-specific constants and identifiers.
 * @author Misagh Moayyed
 */
public interface MultiFactorAuthenticationConstants extends Serializable {

    /** Attribute name by which the authentication context can be retrieve/placed in the flow.**/
    String CAS_AUTHENTICATION_ATTR_NAME = "casAuthentication";

    /** Attribute name by which the TGT can be retrieve/placed in the flow.**/
    String CAS_TICKET_GRANTING_TICKET_ATTR_NAME = "ticketGrantingTicketId";

    /** Attribute name by which the MFA credentials can be retrieve/placed in the flow.**/
    String CAS_MFA_CREDENTIALS_ATTR_NAME = "mfaCredentials";
}
