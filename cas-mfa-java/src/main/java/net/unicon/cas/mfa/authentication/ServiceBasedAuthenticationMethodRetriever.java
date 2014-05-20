package net.unicon.cas.mfa.authentication;

import org.jasig.cas.authentication.principal.WebApplicationService;

/**
 * Strategy interface defining a contract for retrieving requested authentication method based on target services
 * acting as requesters for such additional authentication methods.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public interface ServiceBasedAuthenticationMethodRetriever {

    /**
     * Fetch authentication method from the given CAS service.
     *
     * @param webApplicationService target CAS service possibly encapsulating a request for an additional authentication method
     *
     * @return String representation of an authentication method is such exists or null otherwise.
     */
    String getAuthenticationMethodIfAny(WebApplicationService webApplicationService);
}
