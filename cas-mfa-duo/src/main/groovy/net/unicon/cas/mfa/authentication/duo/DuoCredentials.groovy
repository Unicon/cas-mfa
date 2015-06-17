package net.unicon.cas.mfa.authentication.duo

import org.jasig.cas.authentication.principal.Credentials

class DuoCredentials implements Credentials {

    String username
    String signedDuoResponse

    @Override
    String toString() {
        return "[username: " + this.username + "]"
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true
        }
        if (o == null || getClass() != o.getClass()) {
        return false
        }

        final DuoCredentials that = (DuoCredentials) o;
        if (username != null ? !username.equals(that.username) : that.username != null) {
            return false
        }

        return true
    }

    @Override
    int hashCode() {
        username != null ? username.hashCode() : 0;
    }

}
