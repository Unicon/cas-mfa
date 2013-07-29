package net.unicon.cas.mfa.authentication.principal;

import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 *
 * <p>It is the responsibility of the authentication flow of course, to gather and carry on
 * the instance of {@link MultiFactorCredentials} as it knows how to authenticate the user agent
 * and is itself the recipient of each credential identifier.
 * @author Misagh Moayyed
 * @see #getChainedCredentials()
 * @see #getAuthentication()
 */
public class MultiFactorCredentials implements Credentials {

    private static final long serialVersionUID = -2958788799684788738L;

    private Map<String, Credentials> chainedCredentials = new LinkedHashMap<String, Credentials>();

    private List<Authentication> chainedAuthentication = new LinkedList<Authentication>();

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

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

    public int countChainedAuthentications() {
        return this.chainedAuthentication.size();
    }

    /**
     * Add the authentication to the chain, having verified
     * that the resolved principal of the new authentication
     * matches what has been remembered and collected as the principal.
     * @param authentication authentication context to add to the chain
     * @throws UnknownPrincipalMatchException if principal of the authentication does not match the chain
     */
    public void addAuthenticationToChain(final Authentication authentication) throws UnknownPrincipalMatchException {
        if (!doesPrincipalMatchAuthenticationChain(authentication)) {
            logger.warn("Something bad happened!");
            throw new UnknownPrincipalMatchException(authentication);
        }
        this.chainedAuthentication.add(authentication);
    }

    private boolean doesPrincipalMatchAuthenticationChain(final Authentication authentication) {
        for (final Authentication authn : this.chainedAuthentication) {
            final Principal currentPrincipal = authn.getPrincipal();
            final Principal newPrincipal = authentication.getPrincipal();

            if (!newPrincipal.equals(currentPrincipal)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns the authentication object in the authentication chain
     * that is taken as the primary source of authentication
     * and resolved principal. The chain is configured in such a way
     * that the last authentication object is considered as primary.
     * @return the primary authentication context
     */
    public final Authentication getAuthentication() {
        if (!isEmpty()) {
            return this.chainedAuthentication.get(this.chainedAuthentication.size() - 1);
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
}
