package net.unicon.cas.mfa.web.support;

import net.unicon.cas.addons.serviceregistry.RegisteredServiceWithAttributes;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;
import org.jasig.cas.web.support.ArgumentExtractor;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Set;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.*;

/**
 * The multifactor authentication argument extractor, responsible to
 * instruct CAS with the constructed instance of a {@link org.jasig.cas.authentication.principal.WebApplicationService}
 * that is supported based on the configured {@link #supportedAuthenticationMethods}.
 * <p/>
 * The requested authentication method discovery in this implementation is based on registered service extra attribute <b>authn_method</b>
 * <p/>
 * This implementation first checks if the target registered service contains the supported authentication method attribute
 * and uses that to create an mfa supporting service. If that is not the case, only then it delegates to a wrapped
 * <code>MultiFactorAuthenticationArgumentExtractor</code>
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
     * @param authnMethods authn methods
     * @param supportedProtocols supported protocols
     * @param servicesManager services manager
     */
    public RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor(final List<String> authnMethods,
                                                                                final Set<ArgumentExtractor> supportedProtocols,
                                                                                final ServicesManager servicesManager) {
        super(authnMethods, supportedProtocols);
        this.servicesManager = servicesManager;
    }

    @Override
    protected WebApplicationService extractServiceInternal(final HttpServletRequest request) {
        logger.debug("Attempting to extract multifactor authentication method from registered service attribute...");

        final WebApplicationService targetService = getTargetService(request);
        if (targetService == null) {
            return null;
        }

        final RegisteredService registeredService = this.servicesManager.findServiceBy(targetService);
        if (registeredService == null) {
            logger.debug("No registered service is found. Delegating to the next argument extractor in the chain...");
            return null;
        }
        if (!(registeredService instanceof RegisteredServiceWithAttributes)) {
            logger.debug("Registered service is not capable of defining an mfa attribute. Delegating to the next argument extractor in the chain...");
            return null;
        }

        final String authenticationMethod =
                String.class.cast(RegisteredServiceWithAttributes.class.cast(registeredService).getExtraAttributes().get(CONST_PARAM_AUTHN_METHOD));


        if (!StringUtils.hasText(authenticationMethod)) {
            logger.debug("Registered service does not define authentication method attribute [{}]. Delegating to the next argument extractor in the chain...",
                    CONST_PARAM_AUTHN_METHOD);
            return null;
        }

        verifyAuthenticationMethod(authenticationMethod, targetService, request);

        final MultiFactorAuthenticationSupportingWebApplicationService svc =
                new DefaultMultiFactorAuthenticationSupportingWebApplicationService(
                        targetService.getId(), targetService.getId(), targetService.getArtifactId(),
                        getHttpClientIfSingleSignOutEnabled(),
                        authenticationMethod, AuthenticationMethodSource.REGISTERED_SERVICE_DEFINITION);

        logger.debug("Created multifactor authentication request for [{}] with [{}] as [{}] and authentication method definition source [{}].",
                svc.getId(), CONST_PARAM_AUTHN_METHOD,
                svc.getAuthenticationMethod(),
                AuthenticationMethodSource.REGISTERED_SERVICE_DEFINITION);
        return svc;
    }
}
