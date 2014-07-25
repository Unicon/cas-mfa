package net.unicon.cas.mfa.authentication.duo

import org.jasig.cas.authentication.principal.Credentials
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials

class DuoCredentials extends UsernamePasswordCredentials {
    String signedDuoResponse
}
