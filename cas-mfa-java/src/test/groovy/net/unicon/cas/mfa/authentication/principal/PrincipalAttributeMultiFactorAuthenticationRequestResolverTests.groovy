package net.unicon.cas.mfa.authentication.principal

import groovy.util.logging.Slf4j
import net.unicon.cas.mfa.authentication.AuthenticationMethod
import net.unicon.cas.mfa.authentication.JsonBackedAuthenticationMethodConfigurationProvider
import net.unicon.cas.mfa.web.support.DefaultMultiFactorWebApplicationServiceFactory
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService
import net.unicon.cas.mfa.web.support.MultiFactorWebApplicationServiceFactory
import org.jasig.cas.authentication.Authentication
import org.jasig.cas.authentication.principal.Principal
import org.jasig.cas.authentication.principal.Response
import org.jasig.cas.authentication.principal.SimpleWebApplicationServiceImpl
import org.jasig.cas.authentication.principal.WebApplicationService
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Subject
import spock.lang.Unroll

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource

/**
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
@Slf4j
class PrincipalAttributeMultiFactorAuthenticationRequestResolverTests extends Specification {

    static WebApplicationService targetService = new SimpleWebApplicationServiceImpl('test target service')

    @Shared
    def authenticationWithValidPrincipalAttributeFor_strong_two_factor = Stub(Authentication) {
        getPrincipal() >> Stub(Principal) {
            getId() >> 'test principal'
            getAttributes() >> [authn_method: ['strong_two_factor', 'lower_factor']]
        }
    }

    @Shared
    def authenticationWithoutPrincipalAttributeFor_strong_two_factor = Stub(Authentication) {
        getPrincipal() >> Stub(Principal) {
            getAttributes() >> [:]
        }
    }

    MultiFactorWebApplicationServiceFactory mfaWebApplicationServiceFactory = new DefaultMultiFactorWebApplicationServiceFactory(true, null)

    @Subject
    def s1 = [new AuthenticationMethod("strong_two_factor", 1),
              new AuthenticationMethod("lower_factor", 2),
              new AuthenticationMethod("lowest_factor", 3)] as Set

    def loader = new JsonBackedAuthenticationMethodConfigurationProvider(s1)

    def mfaAuthnReqResolverUnderTest =
            new PrincipalAttributeMultiFactorAuthenticationRequestResolver(mfaWebApplicationServiceFactory, loader)

    @Unroll
    def "either authentication OR service OR both null arguments OR no authn_method principal attribute SHOULD result in empty list"() {
        expect:
        mfaAuthnReqResolverUnderTest.resolve(authn, svc, Response.ResponseType.REDIRECT).size() == 0

        where:
        authn                                                          | svc
        null                                                           | null
        authenticationWithValidPrincipalAttributeFor_strong_two_factor | null
        null                                                           | targetService
        authenticationWithoutPrincipalAttributeFor_strong_two_factor   | targetService

    }

    def "correct MultiFactorAuthenticationRequestContext returned when valid service is passed and a principal attribute 'authn_method'"() {
        given:

        def mfaReq = mfaAuthnReqResolverUnderTest.resolve(authenticationWithValidPrincipalAttributeFor_strong_two_factor, targetService,
                Response.ResponseType.REDIRECT)
        def mfaContext = mfaReq.get(0);

        log.warn(mfaContext.mfaService.getId())
        expect:
        mfaContext.mfaService.id == 'test target service'

        and:
        mfaContext.mfaService.authenticationMethod == 'strong_two_factor'

        and:
        mfaContext.mfaService.authenticationMethodSource == AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE
    }

}
