package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

import java.util.List;

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
     * @return mfa service representing the highest possible ranking authentication method or null
     * if implementations are unable to perform such calculation
     */
    MultiFactorAuthenticationSupportingWebApplicationService computeHighestRankingAuthenticationMethod(
            MultiFactorAuthenticationTransactionContext mfaTransaction);

    /**
     * Determine if provided list of previously achieved authentication methods contains any one method stronger that
     * currently requested one. The algorithm and configuration of the ranking strength of the authentication methods
     * should be provided by implementations.
     *
     * @param previouslyAchievedAuthenticationMethods list of previously achieved authentication methods
     * @param requestedAuthenticationMethod requestedAuthenticationMethod
     *
     * @return true if list contains any methods stronger than requested one, and false otherwise
     */
    boolean anyPreviouslyAchievedAuthenticationMethodsStrongerThanRequestedOne(List<String> previouslyAchievedAuthenticationMethods,
                                                                               String requestedAuthenticationMethod);
}
