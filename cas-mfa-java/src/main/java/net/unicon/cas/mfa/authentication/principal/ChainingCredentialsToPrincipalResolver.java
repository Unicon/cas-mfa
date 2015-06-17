package net.unicon.cas.mfa.authentication.principal;

import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.CredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Principal;

import java.util.Iterator;
import java.util.List;

/**
 * This is {@link ChainingCredentialsToPrincipalResolver} that chains a number of
 * principal resolvers together.
 *
 * @author Misagh Moayyed
 */
public final class ChainingCredentialsToPrincipalResolver implements CredentialsToPrincipalResolver {
    private List<CredentialsToPrincipalResolver> chain;

    @Override
    public Principal resolvePrincipal(final Credentials credentials) {
        final Iterator<CredentialsToPrincipalResolver> it = this.chain.iterator();
        while (it.hasNext()) {
            final CredentialsToPrincipalResolver resolver = it.next();
            if (resolver.supports(credentials)) {
                final Principal p = resolver.resolvePrincipal(credentials);
                if (p != null) {
                    return p;
                }
            }
        }
        return null;
    }

    @Override
    public boolean supports(final Credentials credentials) {
        return true;
    }

    public void setChain(final List<CredentialsToPrincipalResolver> chain) {
        this.chain = chain;
    }
}
