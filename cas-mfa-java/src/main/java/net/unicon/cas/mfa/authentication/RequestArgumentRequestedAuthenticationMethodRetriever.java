package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import org.jasig.cas.authentication.principal.WebApplicationService;

/**
 * Implementation of {@link net.unicon.cas.mfa.authentication.ServiceBasedRequestedAuthenticationMethodRetriever} that
 * gets a possible requested additional authentication method from a request parameter encapsulated in
 * {@link net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService} if available.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public class RequestArgumentRequestedAuthenticationMethodRetriever implements
        ServiceBasedRequestedAuthenticationMethodRetriever {

    @Override
    public String getAuthenticationMethodIfAny(final WebApplicationService webApplicationService) {
        return (webApplicationService instanceof MultiFactorAuthenticationSupportingWebApplicationService)
                ? MultiFactorAuthenticationSupportingWebApplicationService.class.cast(webApplicationService).getAuthenticationMethod()
                : null;
    }
}
