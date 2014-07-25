package net.unicon.cas.mfa.authentication.duo

import groovy.util.logging.Slf4j
import org.jasig.cas.authentication.handler.AuthenticationException
import org.jasig.cas.authentication.handler.AuthenticationHandler
import org.jasig.cas.authentication.principal.Credentials

@Slf4j
class DuoAuthenticationHandler implements AuthenticationHandler {

    private final DuoAuthenticationService duoAuthenticationService

    DuoAuthenticationHandler(DuoAuthenticationService duoAuthenticationService) {
        this.duoAuthenticationService = duoAuthenticationService
    }

    @Override
    boolean authenticate(Credentials credentials) throws AuthenticationException {
        final duoCredentials = credentials as DuoCredentials

        // Do an out of band request using the DuoWeb api (encapsulated in DuoAuthenticationService) to the hosted duo service, if it is successful
        // it will return a String containing the username of the successfully authenticated user, but if not - will
        // return a blank String or null otherwise.
        final duoVerifyResponse = this.duoAuthenticationService.authenticate(duoCredentials.signedDuoResponse)
        log.debug("Response from Duo verify: [{}]", duoVerifyResponse)
        final primaryCredentialsUsername = duoCredentials.username
        final isGoodAuthentication = duoVerifyResponse == primaryCredentialsUsername
        if (isGoodAuthentication) {
            log.info("Successful Duo authentication for [{}]", primaryCredentialsUsername)
            return true
        }
        log.error("Duo authentication error! Login username: [{}], Duo response: [{}]", primaryCredentialsUsername ?: 'null', duoVerifyResponse)
        false
    }

    @Override
    boolean supports(Credentials credentials) {
        DuoCredentials.isAssignableFrom(credentials.class)
    }
}
