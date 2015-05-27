package net.unicon.cas.mfa.authentication.principal;

import net.unicon.cas.addons.serviceregistry.RegisteredServiceWithAttributes;
import net.unicon.cas.mfa.authentication.AuthenticationMethodConfigurationProvider;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import net.unicon.cas.mfa.web.support.MultiFactorWebApplicationServiceFactory;
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

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource;

/**
 * Implementation of <code>MultiFactorAuthenticationRequestResolver</code> that resolves
 * potential mfa request based on the configured principal attribute.
 * Note: It is assumed that the attribute value that specifies the
 * authentication method at this time is a single-valued attribute.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon, inc.
 */
public class ServiceSpecificPrincipalAttributeMultiFactorAuthenticationRequestResolver extends
        PrincipalAttributeMultiFactorAuthenticationRequestResolver {

    /**
     * The logger.
     */
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * Mfa service factory.
     */
    private final MultiFactorWebApplicationServiceFactory mfaServiceFactory;

    private final AuthenticationMethodConfigurationProvider authenticationMethodConfiguration;

    private final Map<String, Pattern> translationMap;

    private final ServicesManager servicesManager;


    /**
     * Ctor.
     *
     * @param mfaServiceFactory mfaServiceFactory
     * @param authenticationMethodConfiguration the authentication method loader
     * @param servicesManager a CAS Service Manager instance
     */
    public ServiceSpecificPrincipalAttributeMultiFactorAuthenticationRequestResolver(
             final MultiFactorWebApplicationServiceFactory mfaServiceFactory,
             final AuthenticationMethodConfigurationProvider authenticationMethodConfiguration,
             final ServicesManager servicesManager) {

        super(mfaServiceFactory, authenticationMethodConfiguration);
        this.mfaServiceFactory = mfaServiceFactory;
        this.authenticationMethodConfiguration = authenticationMethodConfiguration;
        this.servicesManager = servicesManager;

        translationMap = new LinkedHashMap<String, Pattern>();
    }

    @Override
    public List<MultiFactorAuthenticationRequestContext> resolve(@NotNull final Authentication authentication,
                                                                 @NotNull final WebApplicationService targetService) {

        String authenticationMethodAttributeName = null;
        final List<MultiFactorAuthenticationRequestContext> list = new ArrayList<MultiFactorAuthenticationRequestContext>();
        if ((authentication != null) && (targetService != null)) {
            final ServiceMfaData serviceMfaData = getServicesAuthenticationData(targetService);

            if (serviceMfaData == null || !serviceMfaData.isValid()) {
                logger.debug("No specific MFA service attributes found. Trying generic 'authn_method' user attribute");
                return super.resolve(authentication, targetService);

            } else {
                logger.debug("Found mfa_role: {}", serviceMfaData);
            }

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
            logger.debug("No multifactor authentication requests could be resolved based on [{}]. Trying generic 'authn_method' attribute",
                    authenticationMethodAttributeName);
            return super.resolve(authentication, targetService);
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
                              AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE);

              return new MultiFactorAuthenticationRequestContext(svc, mfaMethodRank);
          }

          logger.debug("{} did not match {}", attributeValue, serviceMfaData.getAttributePattern());
          return null;
    }

    /**
     * Match will compare the value to the pattern.
     * @param attributePattern the pattern to check
     * @param attributeValue the value to check
     * @return true if a match is found. otherwise false
     */
    private boolean match(final String attributePattern, final String attributeValue) {
        Pattern pattern = translationMap.get(attributePattern);
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

        final Map mfaRole = Map.class.cast(service.getExtraAttributes().get("mfa_role"));
        if (mfaRole == null) {
            return null;
        }

        serviceData.setAttributeName(String.class.cast(mfaRole.get("mfa_attribute_name")));
        serviceData.setAttributePattern(String.class.cast(mfaRole.get("mfa_attribute_pattern")));
        serviceData.setAuthenticationMethod(String.class.cast(service.getExtraAttributes().get("authn_method")));

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
         * @return true if valid data, otherwise false
         */
        public boolean isValid() {
            if (this.authenticationMethod != null && this.attributeName != null && this.attributePattern != null) {
                return true;
            } else {
                logger.info("Something is null: mfa_authn_method ({}), mfa_attribute_name ({}), or mfa_attribute_pattern ({}) ",
                        authenticationMethod, attributeName, attributePattern);
                return false;
            }
        }

        @Override
        public String toString() {
            return String.format("Mfa role-mfaAuthnMethod: %s, attribute: %s, pattern: %s",
                    this.authenticationMethod, this.attributeName, this.attributePattern);
        }
    }

}
