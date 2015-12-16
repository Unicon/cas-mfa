package net.unicon.cas.mfa.authentication.duo

import groovy.util.logging.Slf4j
import org.jasig.cas.MessageDescriptor
import org.jasig.cas.authentication.Credential
import org.jasig.cas.authentication.HandlerResult
import org.jasig.cas.authentication.PreventedException
import org.jasig.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler
import org.jasig.cas.authentication.principal.Principal

import javax.security.auth.login.FailedLoginException
import java.security.GeneralSecurityException

@Slf4j
class DuoAuthenticationHandler extends AbstractPreAndPostProcessingAuthenticationHandler  {

    private final DuoAuthenticationService duoAuthenticationService

    DuoAuthenticationHandler(DuoAuthenticationService duoAuthenticationService) {
        this.duoAuthenticationService = duoAuthenticationService
    }

    @Override
    protected HandlerResult doAuthentication(final Credential credential) throws GeneralSecurityException, PreventedException {
        try {
            final DuoCredentials duoCredential = (DuoCredentials) credential;

            if (!duoCredential.isValid()) {
                throw new GeneralSecurityException("Duo credential validation failed. Ensure a username "
                        + " and the signed Duo response is configured and passed. Credential received: " + duoCredential);
            }

            final String duoVerifyResponse = this.duoAuthenticationService.authenticate(duoCredential.getSignedDuoResponse());
            logger.debug("Response from Duo verify: [{}]", duoVerifyResponse);
            final String primaryCredentialsUsername = duoCredential.getUsername();

            final boolean isGoodAuthentication = duoVerifyResponse.equals(primaryCredentialsUsername);

            if (isGoodAuthentication) {
                logger.info("Successful Duo authentication for [{}]", primaryCredentialsUsername);

                final Principal principal = this.principalFactory.createPrincipal(duoVerifyResponse);
                return createHandlerResult(credential, principal, new ArrayList<MessageDescriptor>());
            }
            throw new FailedLoginException("Duo authentication username "
                    + primaryCredentialsUsername + " does not match Duo response: " + duoVerifyResponse);

        } catch (final Exception e) {
            logger.error(e.getMessage(), e);
            throw new FailedLoginException(e.getMessage());
        }
    }

    @Override
    boolean supports(final Credential credential) {
        DuoCredentials.isAssignableFrom(credential.class)
    }
}
