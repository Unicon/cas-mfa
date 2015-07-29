package net.unicon.cas.mfa.authentication.loc;

import org.springframework.webflow.execution.RequestContext;

/**
 * @author Misagh Moayyed
 */
public interface AuthenticationLocationResolver {

    /**
     * Resolve authentication location.
     *
     * @param context the context
     * @return the authentication location
     */
    AuthenticationLocation resolve(RequestContext context);
}
