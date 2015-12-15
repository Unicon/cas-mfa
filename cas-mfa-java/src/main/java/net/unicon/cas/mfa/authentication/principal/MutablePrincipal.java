package net.unicon.cas.mfa.authentication.principal;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.jasig.cas.authentication.principal.Principal;

import java.util.Hashtable;
import java.util.Map;

/**
 * An extension of {@link Principal} that exposes a
 * mutable instance of {@link #getAttributes()}.
 *
 * @author Misagh Moayyed
 */
public class MutablePrincipal implements Principal {

    private static final long serialVersionUID = 5317684263509240198L;

    private final Hashtable<String, Object> attributesMap;
    private final String id;

    /**
     * Initialize this principal by the given id
     * and start off with an empty set of attributes.
     *
     * @param id the identifier for this principal.
     */
    public MutablePrincipal(final String id) {
        this.attributesMap = new Hashtable<String, Object>();
        this.id = id;
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributesMap;
    }

    @Override
    public final String toString() {
        return this.getId();
    }

    @Override
    public boolean equals(final Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (!Principal.class.isAssignableFrom(obj.getClass())) {
            return false;
        }
        final Principal rhs = (Principal) obj;
        return new EqualsBuilder()
                .append(getId(), rhs.getId())
                .isEquals();
    }

    @Override
    public int hashCode() {
        final HashCodeBuilder bldr = new HashCodeBuilder(13, 17);
        bldr.append(this.getId());
        return bldr.toHashCode();
    }

}
