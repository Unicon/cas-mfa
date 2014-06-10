package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

/**
 * Temporary impl to be used during API design and initial implementation ideas. To be removed.
 */
public class TemporaryMfaMethodRankingStrategy implements RequestedAuthenticationMethodRankingStrategy {

    @Override
    public MultiFactorAuthenticationSupportingWebApplicationService
    computeHighestRankingAuthenticationMethod(final MultiFactorAuthenticationTransactionContext mfaTransaction) {
        //This one just grabs the first one - obviously to be used for the overall API feel and flow structure around it
        return mfaTransaction.getMfaRequests().iterator().next().getMfaService();
    }
}
