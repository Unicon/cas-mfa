package net.unicon.cas.mfa.authentication.principal

import net.unicon.cas.mfa.web.support.MfaWebApplicationServiceFactory
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource
import org.jasig.cas.authentication.Authentication
import org.jasig.cas.authentication.principal.Principal
import org.jasig.cas.authentication.principal.SimpleWebApplicationServiceImpl
import org.jasig.cas.authentication.principal.WebApplicationService
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Subject
import spock.lang.Unroll

/**
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
class PrincipalAttributeMultiFactorAuthenticationRequestResolverTests extends Specification {

    @Shared
    def authenticationWithValidPrincipalAttributeFor_strong_two_factor = Stub(Authentication) {
        getPrincipal() >> Stub(Principal) {
            getId() >> 'test principal'
            getAttributes() >> [authn_method: 'strong_two_factor']
        }
    }

    @Shared
    def authenticationWithoutPrincipalAttributeFor_strong_two_factor = Stub(Authentication) {
        getPrincipal() >> Stub(Principal) {
            getAttributes() >> [:]
        }
    }

    @Shared
    WebApplicationService targetService = new SimpleWebApplicationServiceImpl('test target service')

    @Shared
    MfaWebApplicationServiceFactory mfaWebApplicationServiceFactory = Stub(MfaWebApplicationServiceFactory) {
        create('test target service', 'test target service', null, 'strong_two_factor', AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE) >>
                Stub(MultiFactorAuthenticationSupportingWebApplicationService) {
                    getId() >> 'test target service'
                    getAuthenticationMethod() >> 'strong_two_factor'
                    getAuthenticationMethodSource() >> AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE
                }
    }

    def map = [(AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE as AuthenticationMethodSource): 1]

    @Subject
    def mfaAuthnReqResolverUnderTest = new PrincipalAttributeMultiFactorAuthenticationRequestResolver(mfaWebApplicationServiceFactory,
            [(AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE as AuthenticationMethodSource): 1])

    @Unroll
    def "either authentication OR service OR both null arguments OR no authn_method principal attribute SHOULD result in a null return value"() {
        expect:
        mfaAuthnReqResolverUnderTest.resolve(authn, svc) == null

        where:
        authn                                                          | svc
        null                                                           | null
        authenticationWithValidPrincipalAttributeFor_strong_two_factor | null
        null                                                           | targetService
        authenticationWithoutPrincipalAttributeFor_strong_two_factor   | targetService

    }

    def "correct MultiFactorAuthenticationRequestContext returned when valid target service is passed and THERE IS a principal attribute 'authn_method'"() {
        given:
        def mfaReq = mfaAuthnReqResolverUnderTest.resolve(authenticationWithValidPrincipalAttributeFor_strong_two_factor, targetService)

        expect:
        mfaReq.mfaService.id == 'test target service'

        and:
        mfaReq.mfaService.authenticationMethod == 'strong_two_factor'

        and:
        mfaReq.mfaService.authenticationMethodSource == AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE
    }
}
