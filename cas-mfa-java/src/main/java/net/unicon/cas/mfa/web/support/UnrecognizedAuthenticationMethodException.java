package net.unicon.cas.mfa.web.support;

/**
 * Thrown if an incoming authentication request specified an authentication
 * method that is not supported and/or recognized by the MFA configuration.
 * @author Misagh Moayyed
 * @see MultiFactorAuthenticationArgumentExtractor
 */
public class UnrecognizedAuthenticationMethodException extends RuntimeException {

    private static final long serialVersionUID = -4141126343252978132L;

    private final String authnMethod;

    /**
     * Spin up the exception instance with the requested authentication method.
     * @param authnMethod the unsupported authentication method in the request
     */
    public UnrecognizedAuthenticationMethodException(final String authnMethod) {
        this.authnMethod = authnMethod;
    }

    public final String getAuthenticationMethod() {
        return this.authnMethod;
    }
}
