package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import org.springframework.core.OrderComparator;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;
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
     * The authn method loader.
     */
    private final DefaultAuthenticationMethodConfigurationProvider authenticationMethodConfiguration;

    /**
     * Ctor.
     *
     * @param authenticationMethodConfiguration the authentication method loader
     */
    public OrderedMfaMethodRankingStrategy(final DefaultAuthenticationMethodConfigurationProvider authenticationMethodConfiguration) {
        this.authenticationMethodConfiguration = authenticationMethodConfiguration;
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
    public boolean anyPreviouslyAchievedAuthenticationMethodsStrongerThanRequestedOne(
            final Set<String> previouslyAchievedAuthenticationMethods, final String requestedAuthenticationMethod) {

        Assert.notNull(previouslyAchievedAuthenticationMethods);
        Assert.notNull(requestedAuthenticationMethod);

        if (previouslyAchievedAuthenticationMethods.isEmpty()) {
            return false;
        }

        final Integer requestedRank = getRank(requestedAuthenticationMethod);
        Integer prevRank = null;
        for (final String prevMethod : previouslyAchievedAuthenticationMethods) {
            prevRank = getRank(prevMethod);
            //Lower rank value == stronger (higher order)
            //We also treat equal ranks as 'not stronger'
            if (prevRank <= requestedRank) {
                return true;
            }
        }
        return false;
    }

    /**
     * Retrieve rank value from the internal Map instance variable for the provided mfa method key.
     *
     * @param mfaMethod key to retrieve the rank value for
     *
     * @return rank value
     *
     * @throws IllegalStateException if the Map is mis-configured i.e. does not hold valid (mfaMethod -> rank) configuration data.
     *                               This is totally a config/deployment error as opposed to external input validation error.
     */
    private Integer getRank(final String mfaMethod) throws IllegalStateException {
        final Integer rank = this.authenticationMethodConfiguration.getAuthenticationMethod(mfaMethod).getRank();
        if (rank == null) {
            throw new IllegalStateException("The [mfaRankingConfig] Map is mis-configured. It does not have a ranking value mapping for the"
                    + " [" + mfaMethod + "] authentication method.");
        }
        return rank;
    }
}
