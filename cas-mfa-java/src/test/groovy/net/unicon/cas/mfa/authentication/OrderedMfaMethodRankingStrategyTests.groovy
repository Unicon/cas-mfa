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

    def "correct implementation of OrderedMfaMethodRankingStrategy"() {
        given:
        @Subject
        def rankingStrategyUnderTest = new OrderedMfaMethodRankingStrategy()

        expect:
        rankingStrategyUnderTest.computeHighestRankingAuthenticationMethod(mfaTransactionFixture).authenticationMethodSource == AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE


    }
}

