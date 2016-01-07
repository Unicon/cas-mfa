package net.unicon.cas.mfa.authentication;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.WebApplicationService;

import javax.validation.constraints.NotNull;
import java.util.List;

/**
 * Defines a mechanism that allows the service's attributes to be compared with the users attributes.
 *
 * @author John Gasper
 * @author Unicon, inc.
 */
public interface RegisteredServiceMfaRoleProcessor {

    /**
     * mfa_attribute_name.
     */
    String MFA_ATTRIBUTE_NAME = "mfa_attribute_name";

    /**
     * mfa_attribute_name.
     */
    String MFA_ATTRIBUTE_PATTERN = "mfa_attribute_pattern";

    /**
     * Resolves the authn_method for a given service if it supports mfa_role and the user has the appropriate attribute.
     * @param authentication the user authentication object
     * @param targetService the target service being tested
     * @return a list (usually one) mfa authn request context.
     */
    List<MultiFactorAuthenticationRequestContext> resolve(@NotNull final Authentication authentication,
                                                          @NotNull final WebApplicationService targetService);

}
