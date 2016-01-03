package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.util.MultiFactorUtils;
import org.jasig.cas.authentication.CredentialMetaData;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.principal.Principal;

import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A {@link CompositeAuthentication} implementation that houses an instance of
 * {@link Principal} inside, restricts the {@link #getAuthenticationDate()} to
 * the instance at which this authentication is created and exposes a mutable
 * instance of authentication attributes via {@link #getAttributes()}.
 * @author Misagh Moayyed
 */
public final class DefaultCompositeAuthentication implements CompositeAuthentication {

    private static final long serialVersionUID = 6594344317585898494L;

    private final Principal principal;
    private final Date authenticationDate = new Date();
    private final Map<String, Object> authenticationAttributes;

    /**
     * Initialize this instance with a principal and given authentication attributes.
     * @param p the principal
     * @param attributes attributes for this authentication
     */
    public DefaultCompositeAuthentication(final Principal p, final Map<String, Object> attributes) {
        this.principal = p;
        this.authenticationAttributes = attributes;
    }

    /**
     * Initialize this instance with a principal and an empty {@link Hashtable}.
     * for attributes.
     * @param p the principal
     */
    public DefaultCompositeAuthentication(final Principal p) {
        this(p, new Hashtable<String, Object>());
    }

    @Override
    public Principal getPrincipal() {
        return this.principal;
    }

    @Override
    public Date getAuthenticationDate() {
        return authenticationDate;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.authenticationAttributes;
    }

    @Override
    public List<CredentialMetaData> getCredentials() {
        return null;
    }

    @Override
    public Map<String, HandlerResult> getSuccesses() {
        return null;
    }

    @Override
    public Map<String, Class<? extends Exception>> getFailures() {
        return null;
    }

    @Override
    public Set<String> getSatisfiedAuthenticationMethods() {
        return MultiFactorUtils.getSatisfiedAuthenticationMethods(this);
    }
}
