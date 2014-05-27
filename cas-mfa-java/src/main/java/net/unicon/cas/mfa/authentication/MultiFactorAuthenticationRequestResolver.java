package net.unicon.cas.mfa.authentication;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.WebApplicationService;

/**
 * A strategy interface for resolving requests for multifactor authentication from existing primary authentication data.
 * <p/>
 * Example implementations might use primary authenticated principal's attribute or some other piece of contextual data
 * available in passed in <code>Authentication</code> object instance.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public interface MultiFactorAuthenticationRequestResolver {

    /**
     * Resolve potential {@link net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext} from passed in primary
     * authentication instance, for a passed in target service.
     *
     * @param authentication primary authentication instance
     * @param targetService target service
     *
     * @return instance of <code>MultiFactorAuthenticationRequestContext</code> or null if no mfa request can be resolved
     */
    MultiFactorAuthenticationRequestContext resolve(final Authentication authentication, final WebApplicationService targetService);
}
