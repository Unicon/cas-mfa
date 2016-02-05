package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import net.unicon.cas.mfa.web.support.MultiFactorWebApplicationServiceFactory;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Response.ResponseType;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
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
    private final Object cacheLock = new Object();

    /**
     * the services manager.
     */
    private final ServicesManager servicesManager;

    /**
     * Ctor.
     *
     * @param mfaServiceFactory                 mfaServiceFactory
     * @param authenticationMethodConfiguration the authentication method loader
     * @param servicesManager                   a CAS Service Manager instance
     */
    public DefaultRegisteredServiceMfaRoleProcessorImpl(
            final MultiFactorWebApplicationServiceFactory mfaServiceFactory,
            final AuthenticationMethodConfigurationProvider authenticationMethodConfiguration,
            final ServicesManager servicesManager) {

        this.mfaServiceFactory = mfaServiceFactory;
        this.authenticationMethodConfiguration = authenticationMethodConfiguration;
        this.servicesManager = servicesManager;
        this.patternCache = new ConcurrentHashMap<>();
    }

    /**
     * Resolves the authn_method for a given service if it supports mfa_role and the user has the appropriate attribute.
     *
     * @param authentication the user authentication object
     * @param targetService  the target service being tested
     * @return a list (usually one) mfa authn request context.
     */
    public List<MultiFactorAuthenticationRequestContext> resolve(@NotNull final Authentication authentication,
                                                                 @NotNull final WebApplicationService targetService) {

        String authenticationMethodAttributeName = null;
        final List<MultiFactorAuthenticationRequestContext> list = new ArrayList<>();
        if (authentication != null && targetService != null) {
            final ServiceMfaData serviceMfaData = getServicesAuthenticationData(targetService);

            if (serviceMfaData == null || !serviceMfaData.isValid()) {
                logger.debug("No specific mfa role service attributes found");
                return list;
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
                    logger.debug("No MFA attribute found.");
                }
            }
        }

        if (list.isEmpty()) {
            logger.debug("No multifactor authentication requests could be resolved based on [{}].",
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
     * @param targetService  the target service
     * @return the mfa request context
     */
    private MultiFactorAuthenticationRequestContext getMfaRequestContext(final ServiceMfaData serviceMfaData,
                                                                         final String attributeValue,
                                                                         final WebApplicationService targetService) {
        final RegisteredService registeredService = this.servicesManager.findServiceBy(targetService);

        String method = null;
        if (registeredService.getProperties().containsKey("method")) {
            method = registeredService.getProperties().get("method").getValue();
        }

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
                            targetService.getArtifactId(), "POST".equals(method) ? ResponseType.POST : ResponseType.REDIRECT,
                            serviceMfaData.getAuthenticationMethod(),
                            MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE);

            return new MultiFactorAuthenticationRequestContext(svc, mfaMethodRank);
        }

        logger.trace("{} did not match {}", attributeValue, serviceMfaData.getAttributePattern());
        return null;
    }

    /**
     * Match will compare the value to the pattern.
     *
     * @param attributePattern the pattern to check
     * @param attributeValue   the value to check
     * @return true if a match is found. otherwise false
     */
    private boolean match(final String attributePattern, final String attributeValue) {
        Pattern pattern;

        synchronized (cacheLock) {
            pattern = patternCache.get(attributePattern);

            if (pattern == null) {
                pattern = Pattern.compile(attributePattern);
                patternCache.put(attributePattern, pattern);
            }
        }

        return pattern.matcher(attributeValue).matches();
    }

    /**
     * Looks up the mfa data for a specific service.
     *
     * @param targetService the service to check
     * @return service specific mfa settings
     */
    private ServiceMfaData getServicesAuthenticationData(final WebApplicationService targetService) {
        final RegisteredService registeredService = this.servicesManager.findServiceBy(targetService);
        if (registeredService == null) {
            logger.debug("No registered service is found. Delegating to the next argument extractor in the chain...");
            return null;
        }

        final ServiceMfaData serviceData = new ServiceMfaData();

        if (registeredService.getProperties().containsKey(RegisteredServiceMfaRoleProcessor.MFA_ATTRIBUTE_NAME)) {
            serviceData.setAttributeName(registeredService.getProperties()
                    .get(RegisteredServiceMfaRoleProcessor.MFA_ATTRIBUTE_NAME).getValue());
        }

        if (registeredService.getProperties().containsKey(RegisteredServiceMfaRoleProcessor.MFA_ATTRIBUTE_PATTERN)) {
            serviceData.setAttributePattern(registeredService.getProperties().
                    get(RegisteredServiceMfaRoleProcessor.MFA_ATTRIBUTE_PATTERN).getValue());
        }

        if (registeredService.getProperties().containsKey(MultiFactorAuthenticationRequestResolver.DEFAULT_MFA_METHOD_ATTRIBUTE_NAME)) {
            serviceData.setAuthenticationMethod(registeredService.getProperties().
                    get(MultiFactorAuthenticationRequestResolver.DEFAULT_MFA_METHOD_ATTRIBUTE_NAME).getValue());
        }

        return serviceData;
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
         *
         * @return true if valid data, otherwise false
         */
        public boolean isValid() {
            if (this.attributeName == null) {
                logger.debug("{} cannot be null", MFA_ATTRIBUTE_NAME);
                return false;
            }
            if (this.attributePattern == null) {
                logger.debug("{} cannot be null", MFA_ATTRIBUTE_PATTERN);
                return false;
            }
            if (this.authenticationMethod == null) {
                logger.debug("{} cannot be null", MultiFactorAuthenticationRequestResolver.DEFAULT_MFA_METHOD_ATTRIBUTE_NAME);
                return false;
            }
            return true;
        }

        @Override
        public String toString() {
            return ToStringBuilder.reflectionToString(this);
        }
    }

}
