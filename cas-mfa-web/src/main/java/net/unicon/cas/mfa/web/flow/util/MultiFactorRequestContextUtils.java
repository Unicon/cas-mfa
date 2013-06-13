package net.unicon.cas.mfa.web.flow.util;

import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;

import org.jasig.cas.authentication.Authentication;
import org.springframework.webflow.execution.RequestContext;

/**
 * Utility methods that facilitate retrieval and storage of MFA objects inside {@link RequestContext}.
 * @author Misagh Moayyed
 */
public final class MultiFactorRequestContextUtils {

    /** Attribute name by which the authentication context can be retrieve/placed in the flow.**/
    public static final String CAS_AUTHENTICATION_ATTR_NAME = "casAuthentication";

    /** Attribute name by which the TGT can be retrieve/placed in the flow.**/
    public static final String CAS_TICKET_GRANTING_TICKET_ATTR_NAME = "ticketGrantingTicketId";

    /** Attribute name by which the MFA credentials can be retrieve/placed in the flow.**/
    public static final String CAS_MFA_CREDENTIALS_ATTR_NAME = "mfaCredentials";

    private MultiFactorRequestContextUtils() {
    }

    public static MultiFactorCredentials getMfaCredentials(final RequestContext context) {
        return (MultiFactorCredentials) context.getFlowScope().get(CAS_MFA_CREDENTIALS_ATTR_NAME);
    }

    public static String getTicketGrantingTicketId(final RequestContext context) {
        return (String) context.getFlowScope().get(CAS_TICKET_GRANTING_TICKET_ATTR_NAME);
    }

    public static Authentication getAuthentication(final RequestContext context) {
        return (Authentication) context.getFlowScope().get(CAS_AUTHENTICATION_ATTR_NAME);
    }

    public static void setMfaCredentials(final RequestContext context, final MultiFactorCredentials credentials) {
        context.getFlowScope().put(CAS_MFA_CREDENTIALS_ATTR_NAME, credentials);
    }

    public static void setAuthentifcation(final RequestContext context, final Authentication auth) {
        context.getFlowScope().put(CAS_AUTHENTICATION_ATTR_NAME, auth);
    }

    public static void setTicketGrantingTicketId(final RequestContext context, final String tgtId) {
        context.getFlowScope().put(CAS_TICKET_GRANTING_TICKET_ATTR_NAME, tgtId);
    }
}