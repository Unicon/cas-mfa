package net.unicon.cas.mfa;

import net.unicon.cas.mfa.ticket.UnacceptableMultiFactorAuthenticationMethodException;
import net.unicon.cas.mfa.ticket.UnrecognizedMultiFactorAuthenticationMethodException;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.validation.Assertion;
import org.jasig.cas.validation.Cas20ProtocolValidationSpecification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validate the requested protocol spec, primarily based on the requested authentication method.
 * @author Misagh Moayyed
 * @see net.unicon.cas.mfa.web.MultiFactorServiceValidateController
 */
public class MultiFactorAuthenticationProtocolValidationSpecification extends Cas20ProtocolValidationSpecification {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private String authenticationMethod = null;

    public MultiFactorAuthenticationProtocolValidationSpecification() {
        super();
    }

    public MultiFactorAuthenticationProtocolValidationSpecification(final String authnMethod) {
        this.authenticationMethod = authnMethod;
    }

    public final void setAuthenticationMethod(final String authnMethod) {
        this.authenticationMethod = authnMethod;
    }

    public final String getAuthenticationMethod() {
        return this.authenticationMethod;
    }

    /**
     * {@inheritDoc}
     * <p>Validate the requested authentication method for this validation request.
     * If the produced assertion cannot satisfy the authentication method requested,
     * an instance of {@link UnacceptableMultiFactorAuthenticationMethodException} will be thrown.
     * If the authentication method used by the assertion is not blank, but does not match
     * the requested authentication method, an instance of {@link UnrecognizedMultiFactorAuthenticationMethodException}
     * will be thrown.
     *
     * <p>Note: The current {@link #isSatisfiedByInternal(Assertion)} method signature
     * only allows for returning of a boolean value indicating whether the assertion
     * can satisfy the requested protocol. This is not sufficient to fully explain the context
     * of a validation failure, as in the case of multifactor authentication, whether
     * the authentication method is unrecognized or unacceptable. In order to accommodate this,
     * and rather than changing the method signature to return more than just a boolean, the
     * implementation opts to throwing specific exceptions in order to indicate the context
     * of the failure. Exceptions are unchecked, yet are expected to be caught by the caller
     * in order to digest the failure.
     *
     * @see UnacceptableMultiFactorAuthenticationMethodException
     * @see UnrecognizedMultiFactorAuthenticationMethodException
     */
    @Override
    protected boolean isSatisfiedByInternal(final Assertion assertion) {
        if (assertion.getChainedAuthentications().size() > 0) {
            final int index = assertion.getChainedAuthentications().size() - 1;
            final Authentication authencation = assertion.getChainedAuthentications().get(index);

            final String authnMethodUsed = (String) authencation.getAttributes()
                    .get(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD);
            if (!StringUtils.isBlank(getAuthenticationMethod())) {
                if (StringUtils.isBlank(authnMethodUsed)) {
                    final String msg = String.format("Requested authentication method [%s] is not available", getAuthenticationMethod());
                    logger.debug(msg);
                    throw new UnacceptableMultiFactorAuthenticationMethodException("UNACCEPTABLE_AUTHENTICATION_METHOD", msg,
                            getAuthenticationMethod());
                }

                if (!authnMethodUsed.equals(getAuthenticationMethod())) {
                    final String msg = String.format("Requested authentication method [%s] does not "
                            + "match the authentication method used [%s]", getAuthenticationMethod(), authnMethodUsed);
                    logger.debug(msg);
                    throw new UnrecognizedMultiFactorAuthenticationMethodException("UNRECOGNIZED_AUTHENTICATION_METHOD", msg,
                            getAuthenticationMethod());
                }
            }

            return true;
        }
        logger.debug("No authentication context is available");
        return false;
    }
}
