package net.unicon.cas.mfa.web.support;

import net.unicon.cas.addons.serviceregistry.RegisteredServiceWithAttributes;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;
import org.jasig.cas.web.support.ArgumentExtractor;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource;
import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD;

/**
 * The multifactor authentication argument extractor, responsible to
 * instruct CAS with the constructed instance of a {@link org.jasig.cas.authentication.principal.WebApplicationService}.
 * The requested authentication method discovery in this implementation is based on registered service extra attribute <b>authn_method</b>
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public final class RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor extends
        AbstractMultiFactorAuthenticationArgumentExtractor {

    private String authenticationMethodAttribute = CONST_PARAM_AUTHN_METHOD;

    /**
     * Services manager.
     */
    private final ServicesManager servicesManager;

    /** The default authentication method to use/force, if service does not specify any. **/
    private String defaultAuthenticationMethod = null;

    /**
     * Ctor.
     *
     * @param supportedArgumentExtractors supported protocols by argument extractors
     * @param mfaWebApplicationServiceFactory mfaWebApplicationServiceFactory
     * @param servicesManager services manager
     * @param authenticationMethodVerifier authenticationMethodVerifier
     */
    public RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor(final List<ArgumentExtractor> supportedArgumentExtractors,
                                                              final MultiFactorWebApplicationServiceFactory mfaWebApplicationServiceFactory,
                                                              final ServicesManager servicesManager,
                                                              final AuthenticationMethodVerifier authenticationMethodVerifier) {
        super(supportedArgumentExtractors, mfaWebApplicationServiceFactory, authenticationMethodVerifier);
        this.servicesManager = servicesManager;
    }

    public void setAuthenticationMethodAttribute(final String authenticationMethodAttribute) {
        this.authenticationMethodAttribute = authenticationMethodAttribute;
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
            logger.debug("Registered service is not capable of defining an mfa attribute. ");
            return determineDefaultAuthenticationMethod();
        }

        final String authenticationMethod =
                String.class.cast(RegisteredServiceWithAttributes.class.cast(registeredService)
                        .getExtraAttributes().get(this.authenticationMethodAttribute));


        if (!StringUtils.hasText(authenticationMethod)) {
            logger.debug("Registered service does not define authentication method attribute [{}]. ",
                    this.authenticationMethodAttribute);
            return determineDefaultAuthenticationMethod();
        }

        return authenticationMethod;
    }

    @Override
    protected AuthenticationMethodSource getAuthenticationMethodSource() {
        return AuthenticationMethodSource.REGISTERED_SERVICE_DEFINITION;
    }

    public void setDefaultAuthenticationMethod(final String defaultAuthenticationMethod) {
        this.defaultAuthenticationMethod = defaultAuthenticationMethod;
    }

    /**
     * Determine default authentication method.
     *
     * @return the default authn method if one is specified, or null.
     */
    protected String determineDefaultAuthenticationMethod() {
        if (!StringUtils.isEmpty(this.defaultAuthenticationMethod)) {
            logger.debug("{} is configured to use the default authentication method [{}]. ",
                    this.getClass().getSimpleName(),
                    this.defaultAuthenticationMethod);
            return this.defaultAuthenticationMethod;
        }
        logger.debug("No default authentication method is defined. Returning null...");
        return null;
    }
}
