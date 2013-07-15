package net.unicon.cas.mfa.authentication.principal;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Principal;

/**
 * A {@link Credentials} implementation that is to ease multi-factor authentication.
 * It primarily carries the following entities:
 * <p>
 * <ul>
 *  <li><strong>Chain of credentials:</strong> represent various forms of credentials during an MFA flow</li>
 *  <li><strong>Chain of authentications:</strong> represent the authentication contexts established during the flow
 *      when credentials are verified.
 *  </li>
 * </ul>
 * <p>Because the {@link Credentials} itself is simply a marker interface, it is up to each credential
 * implementation in the chain to decide how it wants to identify itself. This identifier will be used
 * to locate the particular credential entry in the collection.
 *
 * <p>The collection of established authentication contexts are ordered, in such a way that
 * each entry in the collection is linked to corresponding leg in the authentication flow.
 * By default, the first context is designated to be the <i>primary</i> authentication context, out of which
 * the principal will be taken into consideration.
 *
 * <p>It is the responsibility of the authentication flow of course, to gather and carry on
 * the instance of {@link MultiFactorCredentials} as it knows how to authenticate the user agent
 * and is itself the recipient of each credential identifier.
 * @author Misagh Moayyed
 * @see #getChainedAuthentications()
 * @see #getChainedCredentials()
 * @see #getAuthentication()
 */
public class MultiFactorCredentials implements Credentials {

    private static final long serialVersionUID = -2958788799684788738L;

    private Map<String, Credentials> chainedCredentials = new LinkedHashMap<String, Credentials>();

    private List<Authentication> chainedAuthentication = new LinkedList<Authentication>();

    public final Map<String, Credentials> getChainedCredentials() {
        return this.chainedCredentials;
    }

    /**
     * Indicate whether or not the authentication chain is empty.
     * @return true, if the context is empty.
     */
    public final boolean isEmpty() {
        return this.chainedAuthentication.isEmpty();
    }

    /**
     * A mutable ordered collection of authentication contexts
     * that are collected during the authentication flow.
     * The order corresponds to how the flow consumes credentials
     * and establishes the context.
     * @return authentication contexts
     */
    public final Collection<Authentication> getChainedAuthentications() {
        return this.chainedAuthentication;
    }

    /**
     * Returns the authentication object indicated by {@link #getPrimaryAuthenticationContextIndex()}
     * in the authentication chain hat is taken as the primary source of authentication
     * and resolved principal.
     * @return the primary authentication context
     * @see #getPrimaryAuthenticationContextIndex()
     */
    public final Authentication getAuthentication() {
        if (!isEmpty() && getPrimaryAuthenticationContextIndex() <= this.chainedAuthentication.size()) {
            return this.chainedAuthentication.get(getPrimaryAuthenticationContextIndex());
        }
        return null;
    }

    /**
     * Provides the ability to access the resolved
     * and primary principal based on the authentication context.
     * @return the primary principal.
     */
    public final Principal getPrincipal() {
        if (getAuthentication() != null) {
            return getAuthentication().getPrincipal();
        }
        return null;
    }

    public final Credentials getCredentials() {
        return getChainedCredentials().values().iterator().next();
    }

    /**
     * The index in the authentication chain that
     * would decide which context should be considered as the
     * primary authentication, based on which principals are taken
     * into account.
     * @see #getAuthentication()
     * @return the primary authentication context index
     */
    private int getPrimaryAuthenticationContextIndex() {
        return 0;
    }
}
