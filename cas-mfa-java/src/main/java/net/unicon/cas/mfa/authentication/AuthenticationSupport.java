package net.unicon.cas.mfa.authentication;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Principal;

import java.util.Map;

/**
 * Helper strategy API to ease retrieving CAS' <code>Authentication</code> object and its associated components
 * from available CAS SSO String token called <i>Ticket Granting Ticket (TGT)</i>.
 * <p/>
 * <p>Note: this API is only intended to be called by CAS server code e.g. any custom CAS server overlay extension, etc.</p>
 * <p/>
 * <p>Concurrency semantics: implementations must be thread safe.</p>
 *
 * @author Dmitriy Kopylenko
 * @author Unicon, inc.
 */
public interface AuthenticationSupport {

    /**
     * Retrieve a valid Authentication object identified by the provided TGT SSO token.
     *
     * @param ticketGrantingTicketId an SSO token identifying the requested Authentication
     * @return valid Authentication OR <b>NULL</b> if there is no valid SSO session present identified by the provided TGT id SSO token
     * @throws RuntimeException the runtime exception
     */
    Authentication getAuthenticationFrom(String ticketGrantingTicketId) throws RuntimeException;

    /**
     * Retrieve a valid Principal object identified by the provided TGT SSO token.
     *
     * @param ticketGrantingTicketId an SSO token identifying the requested authenticated Principal
     * @return valid Principal OR <b>NULL</b> if there is no valid SSO session present identified by the provided TGT id SSO token
     * @throws RuntimeException the runtime exception
     */
    Principal getAuthenticatedPrincipalFrom(String ticketGrantingTicketId) throws RuntimeException;

    /**
     * Retrieve a valid Principal's map of attributes identified by the provided TGT SSO token.
     *
     * @param ticketGrantingTicketId an SSO token identifying the requested authenticated Principal's attributes
     * @return valid Principal's attributes OR <b>NULL</b> if there is no valid SSO
     * ession present identified by the provided TGT id SSO token
     * @throws RuntimeException the runtime exception
     */
    Map<String, Object> getPrincipalAttributesFrom(String ticketGrantingTicketId) throws RuntimeException;
}
