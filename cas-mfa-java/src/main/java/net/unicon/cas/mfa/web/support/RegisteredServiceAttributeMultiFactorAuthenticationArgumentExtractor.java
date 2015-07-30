package net.unicon.cas.mfa.web.support;

import net.unicon.cas.addons.authentication.AuthenticationSupport;
import net.unicon.cas.addons.serviceregistry.RegisteredServiceWithAttributes;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext;
import net.unicon.cas.mfa.authentication.RegisteredServiceMfaRoleProcessor;
import org.apache.commons.lang.StringUtils;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;
import org.jasig.cas.web.support.ArgumentExtractor;

import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.execution.RequestContextHolder;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

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
     * The mfa_role processor.
     */
    private RegisteredServiceMfaRoleProcessor mfaRoleProcessor;

    /**
     * The authentication support.
     */
    private AuthenticationSupport authenticationSupport;

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

    @Override
    protected String getAuthenticationMethod(final HttpServletRequest request, final WebApplicationService targetService) {
        logger.debug("Attempting to extract multifactor authentication method from registered service attribute...");

        if (mfaRoleProcessor != null) {
            final String mfaRolesResult = checkMfaRoles(targetService);
            if (!StringUtils.isEmpty(mfaRolesResult)) {
                return mfaRolesResult;
            }
        }

        final RegisteredService registeredService = this.servicesManager.findServiceBy(targetService);
        if (registeredService == null) {
            logger.debug("No registered service is found. Delegating to the next argument extractor in the chain...");
            return null;
        }
        if (!(registeredService instanceof RegisteredServiceWithAttributes)) {
            logger.debug("Registered service is not capable of defining an mfa attribute. ");
            return determineDefaultAuthenticationMethod();
        }

        final Map<String, Object> extraAttributes = RegisteredServiceWithAttributes.class.cast(registeredService)
                .getExtraAttributes();

        if (extraAttributes != null && extraAttributes.containsKey("mfa_role")) {
            logger.debug("Deferring mfa authn method for Principal Attribute Resolver");
            return null;
        }

        final String authenticationMethod =
                String.class.cast(extraAttributes.get(this.authenticationMethodAttribute));


        if (StringUtils.isBlank(authenticationMethod)) {
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
        if (StringUtils.isNotBlank(this.defaultAuthenticationMethod)) {
            logger.debug("{} is configured to use the default authentication method [{}]. ",
                    this.getClass().getSimpleName(),
                    this.defaultAuthenticationMethod);
            return this.defaultAuthenticationMethod;
        }
        logger.debug("No default authentication method is defined. Returning null...");
        return null;
    }

    /**
     * Adaptes the current request to check user attributes.
     * @param targetService the targetted service
     * @return the mfa authn method
     */
    protected String checkMfaRoles(final WebApplicationService targetService) {
        final RequestContext context = RequestContextHolder.getRequestContext();
        if (context == null) {
            logger.debug("No request context is available, so skipping check for mfa role attributes.");
            return null;
        }

        final String tgt = context.getFlowScope().getString("ticketGrantingTicketId");
        if (StringUtils.isBlank(tgt)) {
            logger.debug("The tgt is not available in the flowscope, so skipping check for mfa role attributes.");
            return null;
        }

        final Authentication authentication = this.authenticationSupport.getAuthenticationFrom(tgt);
        if (authentication == null) {
            logger.debug("There is no current authentication, so skipping check for mfa role attributes.");
            return null;
        }

        final List<MultiFactorAuthenticationRequestContext> mfaRequestContexts = mfaRoleProcessor.resolve(authentication, targetService);
        if (mfaRequestContexts == null || mfaRequestContexts.size() == 0) {
            logger.debug("no 'mfa_role' assigned contexts were found.");
            return null;
        }

        final String authnMethod = mfaRequestContexts.get(0).getMfaService().getAuthenticationMethod();
        logger.info("'mfa_role' returned {}.", authnMethod);
        return authnMethod;
    }



    public void setMfaRoleProcessor(final RegisteredServiceMfaRoleProcessor mfaRoleProcessor) {
        this.mfaRoleProcessor = mfaRoleProcessor;
    }

    public void setAuthenticationMethodAttribute(final String authenticationMethodAttribute) {
        this.authenticationMethodAttribute = authenticationMethodAttribute;
    }

    public void setAuthenticationSupport(final AuthenticationSupport authenticationSupport) {
        this.authenticationSupport = authenticationSupport;
    }
}
