package net.unicon.cas.mfa.authentication.principal;

import java.util.Collection;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import net.unicon.cas.mfa.authentication.DefaultCompositeAuthentication;
import net.unicon.cas.mfa.util.MultiFactorUtils;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link Credentials} implementation that is to ease multifactor authentication.
 * It primarily carries the following entities:
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

    /**
     * Count the number of authentication contexts in the chain.
     * @return total number of authentications in the chain.
     */
    public final int countChainedAuthentications() {
        return this.chainedAuthentication.size();
    }

    /**
     * Add the authentication to the chain, having verified
     * that the resolved principal of the new authentication
     * matches what has been remembered and collected as the principal.
     * @param authentication authentication context to add to the chain
     */
    public final void addAuthenticationToChain(final Authentication authentication) {
        if (!doesPrincipalMatchAuthenticationChain(authentication)) {
            logger.warn("The provided principal [{}] does not match the authentication chain. CAS has no record of "
                    + "this principal ever having authenticated in the active authentication context.",
                    authentication.getPrincipal());
            throw new UnknownPrincipalMatchException(authentication);
        }
        this.chainedAuthentication.add(authentication);
    }

    /**
     * Enumerates the list of available principals in the authentication chain
     * and ensures that the newly given and provided principal is compliant
     * and equals the rest of the principals in the chain. The match
     * is explicitly controlled by {@link MutablePrincipal#equals(Object)}
     * implementation.
     *
     * @param authentication the authentication object whose principal is compared against the chain
     * @return true if no mismatch is found; false otherwise.
     * @see MutablePrincipal
     */
    private boolean doesPrincipalMatchAuthenticationChain(final Authentication authentication) {
        for (final Authentication authn : this.chainedAuthentication) {
            final Principal currentPrincipal = authn.getPrincipal();
            final Principal newPrincipal = authentication.getPrincipal();

            if (!currentPrincipal.equals(newPrincipal)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Creates an instance of the {@link net.unicon.cas.mfa.authentication.CompositeAuthentication} object that collects
     * and harmonizes all principal and authentication attributes into one context.
     *
     * <p>Principal attributes are merged from all principals that are already resolved in the authentication chain.
     * Attributes with the same name that belong to the same principal are merged into one, with the latter value
     * overwriting the first. The established principal will be one that is based of {@link MutablePrincipal}.</p>
     *
     * <p>Authentication attributes are merged from all authentications that make up the chain.
     * The merging strategy is such that duplicate attribute names are grouped together into an instance of
     * a {@link Collection} implementation and preserved.
     * @return an instance of {@link net.unicon.cas.mfa.authentication.CompositeAuthentication}
     */
    public final Authentication getAuthentication() {
        if (!isEmpty()) {
            /**
             * Principal id is and must be enforced to be the same for all authentication contexts.
             * Based on that restriction, it's safe to simply grab the first principal id in the chain
             * when composing the authentication chain for the caller.
             */
            final String principalId = this.chainedAuthentication.get(0).getPrincipal().getId();
            final MutablePrincipal compositePrincipal = new MutablePrincipal(principalId);

            final Map<String, Object> authenticationAttributes = new Hashtable<String, Object>();

            for (final Authentication authn : this.chainedAuthentication) {
                final Principal authenticatedPrincipal = authn.getPrincipal();
                compositePrincipal.getAttributes().putAll(authenticatedPrincipal.getAttributes());

                for (final String attrName : authn.getAttributes().keySet()) {
                    if (!authenticationAttributes.containsKey(attrName)) {
                        authenticationAttributes.put(attrName, authn.getAttributes().get(attrName));
                    } else {
                        final Object oldValue = authenticationAttributes.remove(attrName);
                        final Collection<Object> listOfValues = MultiFactorUtils.convertValueToCollection(oldValue);

                        listOfValues.add(authn.getAttributes().get(attrName));
                        authenticationAttributes.put(attrName, listOfValues);
                    }
                }
            }

            return new DefaultCompositeAuthentication(compositePrincipal, authenticationAttributes);
        }
        return null;
    }

    /**
     * Provides the ability to access the resolved
     * and primary principal based on the authentication context.
     * @return the primary principal.
     */
    public final Principal getPrincipal() {
        final Authentication auth = this.getAuthentication();
        if (auth != null) {
            return auth.getPrincipal();
        }
        return null;
    }

    public final Credentials getCredentials() {
        return getChainedCredentials().values().iterator().next();
    }
}
