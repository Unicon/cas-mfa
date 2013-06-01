package net.unicon.cas.mfa.authentication.principal;

import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Principal;

/**
 *
 * @author Misagh Moayyed
 *
 */
public class MultiFactorCredentials implements Credentials {

    private static final long serialVersionUID = -2958788799684788738L;

    private Map<String, Credentials> chainedCredentials = new LinkedHashMap<String, Credentials>();

    private List<Authentication> chainedAuthentication = new LinkedList<Authentication>();

    public final Map<String, Credentials> getChainedCredentials() {
        return this.chainedCredentials;
    }

    public final boolean isEmpty() {
        return this.chainedAuthentication.isEmpty();
    }

    public final List<Authentication> getChainedAuthentication() {
        return this.chainedAuthentication;
    }

    public final Authentication getAuthentication() {
        if (!isEmpty()) {
            return this.chainedAuthentication.get(0);
        }
        return null;
    }

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
