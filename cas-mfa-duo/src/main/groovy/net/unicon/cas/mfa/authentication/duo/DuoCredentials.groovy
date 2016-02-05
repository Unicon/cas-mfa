package net.unicon.cas.mfa.authentication.duo

import org.apache.commons.lang3.StringUtils
import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder
import org.apache.commons.lang3.builder.ToStringBuilder
import org.jasig.cas.authentication.Credential

class DuoCredentials implements Credential, Serializable {

    private String username;
    private String signedDuoResponse;

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("username", this.username)
                .toString();
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof DuoCredentials)) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        final DuoCredentials other = (DuoCredentials) obj;
        final EqualsBuilder builder = new EqualsBuilder();
        builder.append(this.username, other.username);
        return builder.isEquals();
    }

    @Override
    public int hashCode() {
        final HashCodeBuilder builder = new HashCodeBuilder(97, 31);
        builder.append(this.username);
        return builder.toHashCode();
    }

    @Override
    public String getId() {
        return this.username;
    }

    public String getSignedDuoResponse() {
        return signedDuoResponse;
    }

    public String getUsername() {
        return username;
    }


    public void setUsername(final String username) {
        this.username = username;
    }

    public void setSignedDuoResponse(final String signedDuoResponse) {
        this.signedDuoResponse = signedDuoResponse;
    }

    public boolean isValid() {
        return StringUtils.isNotBlank(this.username) && StringUtils.isNotBlank(this.signedDuoResponse);
    }
}
