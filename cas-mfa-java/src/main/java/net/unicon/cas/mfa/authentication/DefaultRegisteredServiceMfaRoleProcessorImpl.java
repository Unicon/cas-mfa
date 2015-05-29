package net.unicon.cas.mfa.authentication;

import net.unicon.cas.addons.serviceregistry.RegisteredServiceWithAttributes;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import net.unicon.cas.mfa.web.support.MultiFactorWebApplicationServiceFactory;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Resolves potential mfa request based on the configured principal attribute and the service attribute.
 * If a service has an mfa-role attribute, then its authn_method is only enforce if the principal matches the requested attribute.
 *
 * @author John Gasper
 * @author Unicon, inc.
 */

public class DefaultRegisteredServiceMfaRoleProcessorImpl implements RegisteredServiceMfaRoleProcessor {
    /**
     * mfa_role.
     */
    public static final String MFA_ROLE = "mfa_role";

    /**
     * mfa_attribute_name.
     */
    public static final String MFA_ATTRIBUTE_NAME = "mfa_attribute_name";

    /**
     * mfa_attribute_name.
     */
    public static final String MFA_ATTRIBUTE_PATTERN = "mfa_attribute_pattern";

    /**
     * authn_method.
     */
    public static final String AUTHN_METHOD = "authn_method";

    /**
     * The logger.
     */
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * Mfa service factory.
     */
    private final MultiFactorWebApplicationServiceFactory mfaServiceFactory;

    /**
     * Authentication Method Configuration Provider.
     */
    private final AuthenticationMethodConfigurationProvider authenticationMethodConfiguration;

    /**
     * used to cache regex patterns for faster lookup/execution.
     */
    private final Map<String, Pattern> patternCache;

    /**
     * the services manager.
     */
    private final ServicesManager servicesManager;


    /**
     * Ctor.
     *
     * @param mfaServiceFactory mfaServiceFactory
     * @param authenticationMethodConfiguration the authentication method loader
     * @param servicesManager a CAS Service Manager instance
     */
    public DefaultRegisteredServiceMfaRoleProcessorImpl(
            final MultiFactorWebApplicationServiceFactory mfaServiceFactory,
            final AuthenticationMethodConfigurationProvider authenticationMethodConfiguration,
            final ServicesManager servicesManager) {

        this.mfaServiceFactory = mfaServiceFactory;
        this.authenticationMethodConfiguration = authenticationMethodConfiguration;
        this.servicesManager = servicesManager;
        this.patternCache = new LinkedHashMap<String, Pattern>();
    }

    /**
     * Resolves the authn_method for a given service if it supports mfa_role and the user has the appropriate attribute.
     * @param authentication the user authentication object
     * @param targetService the target service being tested
     * @return a list (usually one) mfa authn request context.
     */
    public List<MultiFactorAuthenticationRequestContext> resolve(@NotNull final Authentication authentication,
                                                                 @NotNull final WebApplicationService targetService) {

        String authenticationMethodAttributeName = null;
        final List<MultiFactorAuthenticationRequestContext> list = new ArrayList<MultiFactorAuthenticationRequestContext>();
        if ((authentication != null) && (targetService != null)) {
            final ServiceMfaData serviceMfaData = getServicesAuthenticationData(targetService);

            if (serviceMfaData == null) {
                logger.debug("No specific mfa_role service attributes found");
                return null;
            }

            logger.debug("Found mfa_role: {}", serviceMfaData);

            authenticationMethodAttributeName = serviceMfaData.attributeName;

            final Object mfaAttributeValueAsObject = authentication.getPrincipal().getAttributes().get(serviceMfaData.attributeName);
            if (mfaAttributeValueAsObject != null) {
                if (mfaAttributeValueAsObject instanceof String) {
                    final String mfaAttributeValue = mfaAttributeValueAsObject.toString();
                    final MultiFactorAuthenticationRequestContext ctx = getMfaRequestContext(
                            serviceMfaData, mfaAttributeValue, targetService);
                    if (ctx != null) {
                        list.add(ctx);
                    }
                } else if (mfaAttributeValueAsObject instanceof List) {
                    final List<String> mfaAttributeValues = (List<String>) mfaAttributeValueAsObject;
                    for (final String mfaAttributeValue : mfaAttributeValues) {
                        final MultiFactorAuthenticationRequestContext ctx = getMfaRequestContext(
                                serviceMfaData, mfaAttributeValue, targetService);
                        if (ctx != null) {
                            list.add(ctx);
                        }
                    }
                } else {
                    logger.debug("Not MFA Attribute found.");
                }
            }
        }

        if (list.size() == 0) {
            logger.debug("No multifactor authentication requests could be resolved based on [{}]." ,
                    authenticationMethodAttributeName);
            return null;
        }
        return list;
    }

    /**
     * Gets mfa request context.
     *
     * @param serviceMfaData service specific mfa settings
     * @param attributeValue the value found in the attribute
     * @param targetService the target service
     * @return the mfa request context
     */
    private MultiFactorAuthenticationRequestContext getMfaRequestContext(final ServiceMfaData serviceMfaData,
                                                                         final String attributeValue,
                                                                         final WebApplicationService targetService) {

        if (match(serviceMfaData.getAttributePattern(), attributeValue)) {
            if (!this.authenticationMethodConfiguration.containsAuthenticationMethod(serviceMfaData.getAuthenticationMethod())) {
                logger.info("MFA attribute [{}] with value [{}] is not supported by the authentication method configuration.",
                        serviceMfaData.getAttributeName(),
                        serviceMfaData.getAuthenticationMethod());
                return null;
            }
            final int mfaMethodRank = this.authenticationMethodConfiguration.getAuthenticationMethod(
                    serviceMfaData.getAuthenticationMethod()).getRank();
            final MultiFactorAuthenticationSupportingWebApplicationService svc =
                    this.mfaServiceFactory.create(targetService.getId(), targetService.getId(),
                            targetService.getArtifactId(), serviceMfaData.getAuthenticationMethod(),
                            MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE);

            return new MultiFactorAuthenticationRequestContext(svc, mfaMethodRank);
        }

        logger.trace("{} did not match {}", attributeValue, serviceMfaData.getAttributePattern());
        return null;
    }

    /**
     * Match will compare the value to the pattern.
     * @param attributePattern the pattern to check
     * @param attributeValue the value to check
     * @return true if a match is found. otherwise false
     */
    private boolean match(final String attributePattern, final String attributeValue) {
        Pattern pattern = patternCache.get(attributePattern);
        if (pattern == null) {
            pattern = Pattern.compile(attributePattern);
        }

        return pattern.matcher(attributeValue).matches();
    }

    /**
     * Looks up the mfa data for a specific service.
     * @param targetService the service to check
     * @return service specific mfa settings
     */
    private ServiceMfaData getServicesAuthenticationData(final WebApplicationService targetService) {
        final RegisteredService registeredService = this.servicesManager.findServiceBy(targetService);
        if (registeredService == null) {
            logger.debug("No registered service is found. Delegating to the next argument extractor in the chain...");
            return null;
        }

        if (!(registeredService instanceof RegisteredServiceWithAttributes)) {
            logger.debug("Registered service is not capable of defining an mfa attribute.");
            return null;
        }

        final ServiceMfaData serviceData = new ServiceMfaData();

        final RegisteredServiceWithAttributes service = RegisteredServiceWithAttributes.class.cast(registeredService);

        final Map mfaRole = Map.class.cast(service.getExtraAttributes().get(MFA_ROLE));
        if (mfaRole == null) {
            return null;
        }

        serviceData.setAttributeName(String.class.cast(mfaRole.get(MFA_ATTRIBUTE_NAME)));
        serviceData.setAttributePattern(String.class.cast(mfaRole.get(MFA_ATTRIBUTE_PATTERN)));
        serviceData.setAuthenticationMethod(String.class.cast(service.getExtraAttributes().get(AUTHN_METHOD)));

        if (serviceData.isValid()) {
            return serviceData;
        }

        return null;
    }

    /**
     * A POJO to store data retrieved from the Services Manager.
     */
    private class ServiceMfaData {
        private String authenticationMethod;
        private String attributeName;
        private String attributePattern;

        public String getAuthenticationMethod() {
            return authenticationMethod;
        }

        public void setAuthenticationMethod(final String authenticationMethod) {
            this.authenticationMethod = authenticationMethod;
        }

        public String getAttributeName() {
            return attributeName;
        }

        public void setAttributeName(final String attributeName) {
            this.attributeName = attributeName;
        }

        public String getAttributePattern() {
            return attributePattern;
        }

        public void setAttributePattern(final String attributePattern) {
            this.attributePattern = attributePattern;
        }

        /**
         * Checks the the class stores valid data.
         * @return true if valid data, otherwise false
         */
        public boolean isValid() {
            if (this.authenticationMethod != null && this.attributeName != null && this.attributePattern != null) {
                return true;
            }
            if (this.attributeName == null) {
                logger.warn("'mfa_attribute_name' cannot be null when using '{}'", MFA_ROLE);
                return false;
            }
            if (this.attributePattern == null) {
                logger.warn("'mfa_attribute_pattern' cannot be null when using '{}'", MFA_ROLE);
                return false;
            }

            logger.warn("'authn_method` cannot be null when using '{}'", MFA_ROLE);
            return false;
        }

        @Override
        public String toString() {
            return ToStringBuilder.reflectionToString(this);
        }
    }

}
