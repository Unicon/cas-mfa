package net.unicon.cas.mfa.authentication.principal;

import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestResolver;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.WebApplicationService;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource;

/**
 * Implementation of <code>MultiFactorAuthenticationRequestResolver</code> that resolves
 * potential mfa request based on the configured principal attribute.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon, inc.
 */
public class PrincipalAttributeMultiFactorAuthenticationRequestResolver implements
        MultiFactorAuthenticationRequestResolver {

    /**
     * Principal attribute name for requested mfa method.
     */
    private final String mfaMethodAttributeName;

    /**
     * Ctor.
     *
     * @param mfaMethodAttributeName mfaMethodAttributeName
     */
    public PrincipalAttributeMultiFactorAuthenticationRequestResolver(final String mfaMethodAttributeName) {
        this.mfaMethodAttributeName = mfaMethodAttributeName;
    }

    @Override
    public MultiFactorAuthenticationRequestContext resolve(final Authentication authentication, final WebApplicationService targetService) {
        if ((authentication != null) && (targetService != null)) {
            final String mfaMethod = String.class.cast(authentication.getPrincipal().getAttributes().get(this.mfaMethodAttributeName));
            return (mfaMethod != null)
                    ? new MultiFactorAuthenticationRequestContext(mfaMethod, targetService, AuthenticationMethodSource.PRINCIPAL_ATTRIBUTE)
                    : null;
        }
        return null;
    }

}
