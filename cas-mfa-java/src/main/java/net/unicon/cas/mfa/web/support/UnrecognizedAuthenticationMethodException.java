package net.unicon.cas.mfa.web.support;

/**
 * Thrown if an incoming authentication request specified an authentication
 * method that is not supported and/or recognized by the MFA configuration.
 * @author Misagh Moayyed
 * @see net.unicon.cas.mfa.web.support.AbstractMultiFactorAuthenticationArgumentExtractor
 */
public class UnrecognizedAuthenticationMethodException extends RuntimeException {

    private static final long serialVersionUID = -4141126343252978132L;

    private final String authnMethod;
    private final String service;

    /**
     * Spin up the exception instance with the requested authentication method.
     * @param authnMethod the unsupported authentication method in the request
     * @param service the service we are trying to log into
     */
    public UnrecognizedAuthenticationMethodException(final String authnMethod, final String service) {
        this.authnMethod = authnMethod;
        this.service = service;
    }

    public final String getAuthenticationMethod() {
        return this.authnMethod;
    }

    public final String getService() {
        return this.service;
    }
}
