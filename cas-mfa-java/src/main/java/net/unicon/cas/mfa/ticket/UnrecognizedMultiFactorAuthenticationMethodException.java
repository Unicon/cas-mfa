package net.unicon.cas.mfa.ticket;


/**
 * Multifactor authentication exception that is thrown
 * when the requested authentication method cannot be accepted
 * or isn't support by this CAS server.
 * @author Misagh Moayyed
 * @see net.unicon.cas.mfa.MultiFactorAuthenticationProtocolValidationSpecification
 */
public class UnrecognizedMultiFactorAuthenticationMethodException extends MultiFactorAuthenticationBaseTicketValidationException {

    public UnrecognizedMultiFactorAuthenticationMethodException(final String code, final String msg, final String authnMethod) {
        super(code, msg, authnMethod);
    }

    private static final long serialVersionUID = -8544747236126342213L;
}
