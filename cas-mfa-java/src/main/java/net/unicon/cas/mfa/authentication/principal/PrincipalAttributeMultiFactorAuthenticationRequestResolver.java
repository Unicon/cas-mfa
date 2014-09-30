package net.unicon.cas.mfa.authentication.principal;

import net.unicon.cas.mfa.authentication.AuthenticationMethodConfigurationProvider;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestResolver;
import net.unicon.cas.mfa.web.support.MfaWebApplicationServiceFactory;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import org.apache.commons.lang.StringUtils;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource;

/**
 * Implementation of <code>MultiFactorAuthenticationRequestResolver</code> that resolves
 * potential mfa request based on the configured principal attribute.
 * <p/>
 * Note: It is assumed that the attribute value that specifies the
 * authentication method at this time is a single-valued attribute.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon, inc.
 */
public class PrincipalAttributeMultiFactorAuthenticationRequestResolver implements
        MultiFactorAuthenticationRequestResolver {

    /**
     * The logger.
     */
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * Principal attribute name for requested mfa method.
     * Default value if not provided via constructor is <i>authn_method</i>
     */
    private final String mfaMethodAttributeName;

    /**
     * Mfa service factory.
     */
    private final MfaWebApplicationServiceFactory mfaServiceFactory;

    /**
     * The authn method loader.
     */
    private final AuthenticationMethodConfigurationProvider authenticationMethodConfiguration;

    /**
     * Default principal attribute name for retrieving requested mfa authentication method.
     */
    public static final String DEFAULT_MFA_METHOD_ATTRIBUTE_NAME = "authn_method";

    /**
     * Ctor.
     *
     * @param mfaServiceFactory mfaServiceFactory
     * @param authenticationMethodConfiguration the authentication method loader
     */
    public PrincipalAttributeMultiFactorAuthenticationRequestResolver(final MfaWebApplicationServiceFactory mfaServiceFactory,
                    final AuthenticationMethodConfigurationProvider authenticationMethodConfiguration) {
        this(DEFAULT_MFA_METHOD_ATTRIBUTE_NAME, mfaServiceFactory, authenticationMethodConfiguration);
    }

    /**
     * Ctor.
     *
     * @param mfaMethodAttributeName mfaMethodAttributeName
     * @param mfaServiceFactory mfaServiceFactory
     * @param authenticationMethodConfiguration the authentication method loader
     */
    public PrincipalAttributeMultiFactorAuthenticationRequestResolver(final String mfaMethodAttributeName,
               final MfaWebApplicationServiceFactory mfaServiceFactory,
               final AuthenticationMethodConfigurationProvider authenticationMethodConfiguration) {

        this.mfaMethodAttributeName = mfaMethodAttributeName;
        this.mfaServiceFactory = mfaServiceFactory;
        this.authenticationMethodConfiguration = authenticationMethodConfiguration;
    }

    @Override
    public List<MultiFactorAuthenticationRequestContext> resolve(final Authentication authentication,
                                                                 final WebApplicationService targetService) {
        final List<MultiFactorAuthenticationRequestContext> list = new ArrayList<MultiFactorAuthenticationRequestContext>();
        if ((authentication != null) && (targetService != null)) {
            final Object mfaMethodAsObject = authentication.getPrincipal().getAttributes().get(this.mfaMethodAttributeName);
            if (mfaMethodAsObject != null) {
                if (mfaMethodAsObject instanceof String) {
                    final String mfaMethod = mfaMethodAsObject.toString();
                    final MultiFactorAuthenticationRequestContext ctx = getMfaRequestContext(mfaMethod, authentication, targetService);
                    if (ctx != null) {
                        list.add(ctx);
                    }
                } else if (mfaMethodAsObject instanceof List) {
                    final List<String> mfaMethods = (List<String>) mfaMethodAsObject;
                    for (final String mfaMethod : mfaMethods) {
                        final MultiFactorAuthenticationRequestContext ctx = getMfaRequestContext(mfaMethod, authentication, targetService);
                        if (ctx != null) {
                            list.add(ctx);
                        }
                    }
                }
            }
        }
        return list;
    }

    /**
     * Gets mfa request context.
     *
     * @param mfaMethod the mfa method
     * @param authentication the authentication
     * @param targetService the target service
     * @return the mfa request context
     */
    private MultiFactorAuthenticationRequestContext getMfaRequestContext(final String mfaMethod,
                                                                         final Authentication authentication,
                                                                         final WebApplicationService targetService) {
        if (StringUtils.isNotBlank(mfaMethod)) {
            logger.debug("Found mfa attribute [{}] with value [{}] for principal [{}]", this.mfaMethodAttributeName,
                    mfaMethod, authentication.getPrincipal().getId());

            if (!this.authenticationMethodConfiguration.containsAuthenticationMethod(mfaMethod)) {
                logger.info("MFA attribute [{}] with value [{}] is not supported by the authentication method configuration.",
                        this.mfaMethodAttributeName,
                        mfaMethod);
                return null;
            }
            final int mfaMethodRank = this.authenticationMethodConfiguration.getAuthenticationMethod(mfaMethod).getRank();
            final MultiFactorAuthenticationSupportingWebApplicationService svc =
                    this.mfaServiceFactory.create(targetService.getId(), targetService.getId(),
                            targetService.getArtifactId(), mfaMethod, AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE);

            return new MultiFactorAuthenticationRequestContext(svc, mfaMethodRank);
        }
        return null;
    }
}
