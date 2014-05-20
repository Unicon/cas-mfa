package net.unicon.cas.mfa.authentication;

import net.unicon.cas.addons.serviceregistry.RegisteredServiceWithAttributes;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD;

/**
 * Implementation of {@link ServiceBasedAuthenticationMethodRetriever} that
 * gets a possible requested additional authentication method from a registered service definition's extra attribute
 * for a given target service, if available.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public class RegisteredServiceAuthenticationMethodRetriever implements
        ServiceBasedAuthenticationMethodRetriever {

    /**
     * ServicesManager.
     */
    private final ServicesManager servicesManager;

    /**
     * Ctor.
     *
     * @param servicesManager instance
     */
    public RegisteredServiceAuthenticationMethodRetriever(final ServicesManager servicesManager) {
        this.servicesManager = servicesManager;
    }

    @Override
    public String getAuthenticationMethodIfAny(final WebApplicationService webApplicationService) {
        final RegisteredService registeredService = this.servicesManager.findServiceBy(webApplicationService);
        if (registeredService == null) {
            return null;
        }
        if (registeredService instanceof RegisteredServiceWithAttributes) {
            return String.class.cast(RegisteredServiceWithAttributes.class.cast(registeredService).getExtraAttributes().get(CONST_PARAM_AUTHN_METHOD));
        }
        return null;
    }
}
