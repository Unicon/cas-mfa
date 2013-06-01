package net.unicon.cas.mfa.authentication.principal;

import java.util.Map;

import org.jasig.cas.authentication.principal.SimplePrincipal;

/**
 *
 * @author Misagh Moayyed
 *
 */
public final class MultiFactorPrincipal extends SimplePrincipal {

    private static final long serialVersionUID = -6030898672731311578L;

    public MultiFactorPrincipal(final String id, final Map<String, Object> attributes) {
        super(id, attributes);
    }

    public MultiFactorPrincipal(final String principalId) {
        super(principalId);
    }

}
