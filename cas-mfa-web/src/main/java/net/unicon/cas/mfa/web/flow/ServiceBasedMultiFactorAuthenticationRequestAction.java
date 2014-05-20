package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.addons.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.authentication.ServiceBasedRequestedAuthenticationMethodRetriever;
import org.jasig.cas.authentication.principal.WebApplicationService;


/**
 * Retrieve authentication method from or by means of {@link org.jasig.cas.authentication.principal.WebApplicationService}.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public final class ServiceBasedMultiFactorAuthenticationRequestAction extends AbstractValidateMultiFactorAuthenticationRequestAction {

    /**
     * The authenticationMethodRetriever.
     */
    private final ServiceBasedRequestedAuthenticationMethodRetriever authenticationMethodRetriever;


    /**
     * Ctor.
     *
     * @param authSupport authentication support
     * @param authenticationMethodRetriever authenticationMethodRetriever
     */
    public ServiceBasedMultiFactorAuthenticationRequestAction(final AuthenticationSupport authSupport,
                                                              final ServiceBasedRequestedAuthenticationMethodRetriever authenticationMethodRetriever) {
        super(authSupport);
        this.authenticationMethodRetriever = authenticationMethodRetriever;
    }

    @Override
    protected String retrieveAuthenticationMethodFromService(final WebApplicationService service) {
        return this.authenticationMethodRetriever.getAuthenticationMethodIfAny(service);
    }
}
