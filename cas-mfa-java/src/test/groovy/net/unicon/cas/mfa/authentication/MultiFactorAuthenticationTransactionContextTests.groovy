package net.unicon.cas.mfa.authentication

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService
import org.jasig.cas.authentication.Authentication
import spock.lang.Specification
import spock.lang.Subject
import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource

/**
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
class MultiFactorAuthenticationTransactionContextTests extends Specification {

    def mfaReqViaParam = new MultiFactorAuthenticationRequestContext(Stub(MultiFactorAuthenticationSupportingWebApplicationService) {
        getId() >> 'test service'
        getAuthenticationMethodSource() >> AuthenticationMethodSource.REQUEST_PARAM
    }, 3)

    def mfaReqViaRegSvc = new MultiFactorAuthenticationRequestContext(Stub(MultiFactorAuthenticationSupportingWebApplicationService) {
        getId() >> 'test service'
        getAuthenticationMethodSource() >> AuthenticationMethodSource.REGISTERED_SERVICE_DEFINITION
    }, 2)

    def mfaReqViaPrincipalAttr = new MultiFactorAuthenticationRequestContext(Stub(MultiFactorAuthenticationSupportingWebApplicationService) {
        getId() >> 'second service trying to sneak in somehow'
        getAuthenticationMethodSource() >> AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE
    }, 1)


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
