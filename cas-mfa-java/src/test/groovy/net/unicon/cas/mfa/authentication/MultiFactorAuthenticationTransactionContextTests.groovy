package net.unicon.cas.mfa.authentication

import org.jasig.cas.authentication.Authentication
import org.jasig.cas.authentication.principal.WebApplicationService
import spock.lang.Specification
import spock.lang.Subject
import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource

/**
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
class MultiFactorAuthenticationTransactionContextTests extends Specification {

    def mfaReqViaParam = new MultiFactorAuthenticationRequestContext('strong_mfa', Stub(WebApplicationService) {
        getId() >> 'test service'
    }, AuthenticationMethodSource.REQUEST_PARAM)

    def mfaReqViaRegSvc = new MultiFactorAuthenticationRequestContext('weak_mfa', Stub(WebApplicationService) {
        getId() >> 'test service'
    }, AuthenticationMethodSource.REGISTERED_SERVICE_DEFINITION)

    def mfaReqViaPrincipalAttr = new MultiFactorAuthenticationRequestContext('other_mfa', Stub(WebApplicationService) {
        getId() >> 'second service trying to sneak in somehow'
    }, AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE)


    def "creating an instance with a default constructor results in null primary authentication and empty mfa requests collection"() {
        given:
        @Subject
        def authnTxCtxUnderTest = new MultiFactorAuthenticationTransactionContext('test service')

        expect:
        !authnTxCtxUnderTest.primaryAuthentication

        and:
        authnTxCtxUnderTest.mfaRequests.size() == 0
    }

    def "fluid API works as expected"() {
        given:
        @Subject
        def authnTxCtxUnderTest = new MultiFactorAuthenticationTransactionContext('test service')
                .setPrimaryAuthentication(Mock(Authentication)).addMfaRequest(mfaReqViaParam).addMfaRequest(mfaReqViaRegSvc)

        expect:
        authnTxCtxUnderTest.primaryAuthentication

        and:
        authnTxCtxUnderTest.mfaRequests.size() == 2
    }

    def "no duplicate authentication method source are allowed"() {
        when:
        @Subject
        def authnTxCtxUnderTest = new MultiFactorAuthenticationTransactionContext('test service').addMfaRequest(mfaReqViaParam).addMfaRequest(mfaReqViaParam)

        then:
        thrown(IllegalArgumentException)
    }

    def "unmodifiable Set is returned for mfaRequests property"() {
        given:
        @Subject
        def authnTxCtxUnderTest = new MultiFactorAuthenticationTransactionContext('test service').addMfaRequest(mfaReqViaParam)

        when:
        authnTxCtxUnderTest.mfaRequests << mfaReqViaRegSvc

        then:
        thrown(UnsupportedOperationException)
    }

    def "only single target service is allowed for all mfa requests"() {
        when:
        @Subject
        def authnTxCtxUnderTest = new MultiFactorAuthenticationTransactionContext('test service')
                .addMfaRequest(mfaReqViaParam)
                .addMfaRequest(mfaReqViaPrincipalAttr)

        then:
        thrown(IllegalArgumentException)
    }
}
