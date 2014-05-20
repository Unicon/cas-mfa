package net.unicon.cas.mfa.authentication

import net.unicon.cas.addons.serviceregistry.RegisteredServiceWithAttributesImpl
import org.jasig.cas.authentication.principal.SimpleWebApplicationServiceImpl
import org.jasig.cas.services.RegisteredServiceImpl
import org.jasig.cas.services.ServicesManager
import spock.lang.Specification
import spock.lang.Subject

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD

/**
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
class RegisteredServiceRequestedAuthenticationMethodRetrieverTests extends Specification {

    def registeredServiceWithExtraAttributes_AND_WithAuthnMethod = new RegisteredServiceWithAttributesImpl().with {
        it.extraAttributes[CONST_PARAM_AUTHN_METHOD] = 'strong_two_factor'
        return it
    }

    def registeredServiceWithExtraAttributes_AND_WithoutAuthnMethod = new RegisteredServiceWithAttributesImpl()

    def targetService = new SimpleWebApplicationServiceImpl("test service")

    def regularRegisteredService = new RegisteredServiceImpl()

    def "registered service with extra attributes and defined authn method attribute results in correct authn method return value"() {

        setup:
        def servicesManager = Stub(ServicesManager) {
            findServiceBy(_) >> registeredServiceWithExtraAttributes_AND_WithAuthnMethod
        }
        @Subject
        def retrieverUnderTest = new RegisteredServiceAuthenticationMethodRetriever(servicesManager)

        expect:
        retrieverUnderTest.getAuthenticationMethodIfAny(this.targetService) == 'strong_two_factor'
    }

    def "registered service with extra attributes and NO defined authn method attribute results in null return value"() {

        setup:
        def servicesManager = Stub(ServicesManager) {
            findServiceBy(_) >> registeredServiceWithExtraAttributes_AND_WithoutAuthnMethod
        }
        @Subject
        def retrieverUnderTest = new RegisteredServiceAuthenticationMethodRetriever(servicesManager)

        expect:
        retrieverUnderTest.getAuthenticationMethodIfAny(this.targetService) == null
    }

    def "regular registered service results in null return value"() {

        setup:
        def servicesManager = Stub(ServicesManager) {
            findServiceBy(_) >> regularRegisteredService
        }
        @Subject
        def retrieverUnderTest = new RegisteredServiceAuthenticationMethodRetriever(servicesManager)

        expect:
        retrieverUnderTest.getAuthenticationMethodIfAny(this.targetService) == null
    }

}
