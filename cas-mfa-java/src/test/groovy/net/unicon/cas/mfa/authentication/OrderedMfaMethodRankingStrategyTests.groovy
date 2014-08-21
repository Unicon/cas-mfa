package net.unicon.cas.mfa.authentication

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService
import spock.lang.Subject

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource
import spock.lang.Specification

/**
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
class OrderedMfaMethodRankingStrategyTests extends Specification {

    def mfaTransactionFixture = new MultiFactorAuthenticationTransactionContext("test service")
            .addMfaRequest(new MultiFactorAuthenticationRequestContext(Stub(MultiFactorAuthenticationSupportingWebApplicationService) {
        getId() >> 'test service'
        getAuthenticationMethodSource() >> AuthenticationMethodSource.REQUEST_PARAM

    }, 3)).addMfaRequest(new MultiFactorAuthenticationRequestContext(Stub(MultiFactorAuthenticationSupportingWebApplicationService) {
        getId() >> 'test service'
        getAuthenticationMethodSource() >> AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE

    }, 1)).addMfaRequest(new MultiFactorAuthenticationRequestContext(Stub(MultiFactorAuthenticationSupportingWebApplicationService) {
        getId() >> 'test service'
        getAuthenticationMethodSource() >> AuthenticationMethodSource.REGISTERED_SERVICE_DEFINITION

    }, 2))

    def "correct implementation of OrderedMfaMethodRankingStrategy#computeHighestRankingAuthenticationMethod"() {
        given:
        @Subject
        def rankingStrategyUnderTest = new OrderedMfaMethodRankingStrategy(new DefaultAuthenticationMethodConfigurationProvider())

        expect:
        rankingStrategyUnderTest.computeHighestRankingAuthenticationMethod(mfaTransactionFixture).authenticationMethodSource == AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE
    }

    def "correct implementation of OrderedMfaMethodRankingStrategy#anyPreviouslyAchievedAuthenticationMethodsStrongerThanRequestedOne"() {
        given:
        def s1 = [new AuthenticationMethod("highest_factor",1),
                 new AuthenticationMethod("lower_factor",2),
                 new AuthenticationMethod("lowest_factor",3)] as Set

        def loader = new DefaultAuthenticationMethodConfigurationProvider(s1)
        @Subject
        def rankingStrategyUnderTest = new OrderedMfaMethodRankingStrategy(loader)

        expect:
        rankingStrategyUnderTest.anyPreviouslyAchievedAuthenticationMethodsStrongerThanRequestedOne(['lower_factor', 'highest_factor'] as Set, 'lowest_factor')

        and:
        !rankingStrategyUnderTest.anyPreviouslyAchievedAuthenticationMethodsStrongerThanRequestedOne(['lowest_factor', 'lower_factor'] as Set, 'highest_factor')
    }
}

