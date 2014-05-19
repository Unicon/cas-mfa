package net.unicon.cas.mfa.authentication

import net.unicon.cas.mfa.web.support.DefaultMultiFactorAuthenticationSupportingWebApplicationService
import org.jasig.cas.authentication.principal.SimpleWebApplicationServiceImpl
import spock.lang.Specification

/**
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
class RequestArgumentRequestedAuthenticationMethodRetrieverTests extends Specification {

    def retrieverUnderTest = new RequestArgumentRequestedAuthenticationMethodRetriever()

    def "Service that does not request additional authentication method passed to retriever as argument returns null"() {

        given:
        def service = new SimpleWebApplicationServiceImpl("non-mfa-requesting-service")

        expect:
        this.retrieverUnderTest.getAuthenticationMethodIfAny(service) == null
    }

    def "Service that requests additional authentication method passed to retriever as argument returns authentication method value"() {

        given:
        def service = new DefaultMultiFactorAuthenticationSupportingWebApplicationService(null, null, null, null, 'strong_two_factor')

        expect:
        this.retrieverUnderTest.getAuthenticationMethodIfAny(service) == 'strong_two_factor'
    }
}
