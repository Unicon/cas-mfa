package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import org.springframework.core.OrderComparator;

import java.util.ArrayList;
import java.util.List;

/**
 * Ranking strategy implementation that utilizes {@link org.springframework.core.Ordered} abstraction
 * of {@link net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext}.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon, inc.
 */
public class OrderedMfaMethodRankingStrategy implements RequestedAuthenticationMethodRankingStrategy {

    @Override
    public MultiFactorAuthenticationSupportingWebApplicationService
    computeHighestRankingAuthenticationMethod(final MultiFactorAuthenticationTransactionContext mfaTransaction) {
        final List<MultiFactorAuthenticationRequestContext> sortedRequests =
                new ArrayList<MultiFactorAuthenticationRequestContext>(mfaTransaction.getMfaRequests());

        OrderComparator.sort(sortedRequests);
        return sortedRequests.get(0).getMfaService();
    }
}
