package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

/**
 * Strategy interface for ranking requested authentication methods.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public interface RequestedAuthenticationMethodRankingStrategy {

    /**
     * Calculates the highest ranking possible authentication method from the list of the requested ones.
     *
     * @param mfaTransaction mfa transaction encapsulating possible requested authentication methods
     *
     * @return mfa service representing the highest possible ranking authentication method or null if implementations are unable to perform such calculation
     */
    MultiFactorAuthenticationSupportingWebApplicationService computeHighestRankingAuthenticationMethod(MultiFactorAuthenticationTransactionContext mfaTransaction);
}
