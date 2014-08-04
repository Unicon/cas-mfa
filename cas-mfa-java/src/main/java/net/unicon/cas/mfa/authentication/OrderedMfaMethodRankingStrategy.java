package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import org.springframework.core.OrderComparator;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Ranking strategy implementation that utilizes {@link org.springframework.core.Ordered} abstraction
 * of {@link net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext}.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon, inc.
 */
public class OrderedMfaMethodRankingStrategy implements RequestedAuthenticationMethodRankingStrategy {

    /**
     * A config map with ranking numbers per mfa method type.
     */
    private final Map<String, Integer> mfaRankingConfig;

    /**
     * Ctor.
     *
     * @param mfaRankingConfig the mfa ranking config
     */
    public OrderedMfaMethodRankingStrategy(final Map<String, Integer> mfaRankingConfig) {
        this.mfaRankingConfig = mfaRankingConfig;
    }

    @Override
    public MultiFactorAuthenticationSupportingWebApplicationService
    computeHighestRankingAuthenticationMethod(final MultiFactorAuthenticationTransactionContext mfaTransaction) {
        final List<MultiFactorAuthenticationRequestContext> sortedRequests =
                new ArrayList<MultiFactorAuthenticationRequestContext>(mfaTransaction.getMfaRequests());

        OrderComparator.sort(sortedRequests);
        return sortedRequests.get(0).getMfaService();
    }

    @Override
    public boolean anyPreviouslyAchievedAuthenticationMethodsStrongerThanRequestedOne(final Set<String> previouslyAchievedAuthenticationMethods,
                                                                                      final String requestedAuthenticationMethod) {

        Assert.notNull(previouslyAchievedAuthenticationMethods);
        Assert.notNull(requestedAuthenticationMethod);

        if (previouslyAchievedAuthenticationMethods.isEmpty()) {
            return false;
        }

        final Integer currRank = this.mfaRankingConfig.get(requestedAuthenticationMethod);
        //Treat this as misconfiguration and throw a RuntimeException
        if (currRank == null) {
            throw new RuntimeException("The [mfaRankingConfig] Map is mis-configured. It does not have a ranking value mapping for the"
                    + " [" + requestedAuthenticationMethod + "] authentication method.");
        }
        Integer prevRank = null;
        for (final String prevMethod : previouslyAchievedAuthenticationMethods) {
            prevRank = this.mfaRankingConfig.get(prevMethod);
            //Treat this as misconfiguration and throw a RuntimeException
            if (prevRank == null) {
                throw new RuntimeException("The [mfaRankingConfig] Map is mis-configured. It does not have a ranking value mapping for the"
                        + " [" + prevMethod + "] authentication method.");
            }
            //Lower rank value == stronger (higher order)
            //We also treat equal ranks as 'not stronger'
            if(prevRank < currRank) {
                return true;
            }
        }
        return false;
    }
}
