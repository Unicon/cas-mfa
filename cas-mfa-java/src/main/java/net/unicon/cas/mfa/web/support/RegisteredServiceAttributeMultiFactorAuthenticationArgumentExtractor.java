package net.unicon.cas.mfa.web.support;

import net.unicon.cas.addons.serviceregistry.RegisteredServiceWithAttributes;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;
import org.jasig.cas.web.support.ArgumentExtractor;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Set;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.*;

/**
 * The multifactor authentication argument extractor, responsible to
 * instruct CAS with the constructed instance of a {@link org.jasig.cas.authentication.principal.WebApplicationService}.
 * <p/>
 * The requested authentication method discovery in this implementation is based on registered service extra attribute <b>authn_method</b>
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public final class RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor extends
        AbstractMultiFactorAuthenticationArgumentExtractor {


    /**
     * Services manager.
     */
    private final ServicesManager servicesManager;

    /**
     * Ctor.
     *
     * @param supportedProtocols supported protocols
     * @param mfaWebApplicationServiceFactory mfaWebApplicationServiceFactory
     * @param servicesManager services manager
     * @param authenticationMethodVerifier authenticationMethodVerifier
     */
    public RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor(final Set<ArgumentExtractor> supportedProtocols,
                                                              final MfaWebApplicationServiceFactory mfaWebApplicationServiceFactory,
                                                              final ServicesManager servicesManager,
                                                              final AuthenticationMethodVerifier authenticationMethodVerifier) {
        super(supportedProtocols, mfaWebApplicationServiceFactory, authenticationMethodVerifier);
        this.servicesManager = servicesManager;
    }


    @Override
    protected String getAuthenticationMethod(final HttpServletRequest request, final WebApplicationService targetService) {
        logger.debug("Attempting to extract multifactor authentication method from registered service attribute...");

        final RegisteredService registeredService = this.servicesManager.findServiceBy(targetService);
        if (registeredService == null) {
            logger.debug("No registered service is found. Delegating to the next argument extractor in the chain...");
            return null;
        }
        if (!(registeredService instanceof RegisteredServiceWithAttributes)) {
            logger.debug("Registered service is not capable of defining an mfa attribute."
                    + "Delegating to the next argument extractor in the chain...");
            return null;
        }

        final String authenticationMethod =
                String.class.cast(RegisteredServiceWithAttributes.class.cast(registeredService)
                        .getExtraAttributes().get(CONST_PARAM_AUTHN_METHOD));


        if (!StringUtils.hasText(authenticationMethod)) {
            logger.debug("Registered service does not define authentication method attribute [{}]."
                    + "Delegating to the next argument extractor in the chain...",
                    CONST_PARAM_AUTHN_METHOD);
            return null;
        }

        return authenticationMethod;
    }

    @Override
    protected AuthenticationMethodSource getAuthenticationMethodSource() {
        return AuthenticationMethodSource.REGISTERED_SERVICE_DEFINITION;
    }
}
