package net.unicon.cas.mfa.authentication.duo

import com.duosecurity.DuoWeb

/**
 * An abstraction that encapsulates interaction with Duo 2fa authentication service via its public API
 * <p/>
 * Derived from the fine work of @author Eric Pierce <epierce@usf.edu>
 * and @author Michael Kennedy <michael.kennedy@ucr.edu>
 */
final class DuoAuthenticationService {
    private final String duoIntegrationKey
    private final String duoSecretKey
    private final String duoApplicationKey
    private final String duoApiHost

    DuoAuthenticationService(duoIntegrationKey, duoSecretKey, duoApplicationKey, duoApiHost) {
        this.duoIntegrationKey = duoIntegrationKey
        this.duoSecretKey = duoSecretKey
        this.duoApplicationKey = duoApplicationKey
        this.duoApiHost = duoApiHost
    }

    def getDuoApiHost() {
        this.duoApiHost
    }

    def generateSignedRequestToken(final String username) {
        DuoWeb.signRequest(this.duoIntegrationKey, this.duoSecretKey, this.duoApplicationKey, username)
    }

    def authenticate(final String signedRequestToken) {
        DuoWeb.verifyResponse(this.duoIntegrationKey, this.duoSecretKey, this.duoApplicationKey, signedRequestToken)
    }
}
