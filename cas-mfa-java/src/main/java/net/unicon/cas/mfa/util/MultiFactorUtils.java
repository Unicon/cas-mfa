package net.unicon.cas.mfa.util;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import org.apache.commons.lang3.StringUtils;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.validation.Assertion;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Utility methods to ease implementation of multifactor behavior.
 * @author Misagh Moayyed
 */
public final class MultiFactorUtils {
    /**
     * Private constructor.
     */
    private MultiFactorUtils() {
    }

    /**
     * Generate the string the indicates the list of satisfied authentication methods.
     * Methods are separated by a space.
     * @param assertion the assertion carrying the methods.
     * @return the space-delimited list of authentication methods, or null if none is available
     */
    public static String getFulfilledAuthenticationMethodsAsString(final Assertion assertion) {
        final Authentication authentication = getAuthenticationFromAssertion(assertion);
        return getFulfilledAuthenticationMethodsAsString(authentication);
    }

    /**
     * Generate the string the indicates the list of satisfied authentication methods.
     * Methods are separated by a space.
     * @param authentication the authentication carrying the methods.
     * @return the space-delimited list of authentication methods, or null if none is available
     */
    public static String getFulfilledAuthenticationMethodsAsString(final Authentication authentication) {
        final Set<String> previouslyAchievedAuthenticationMethods = getSatisfiedAuthenticationMethods(authentication);
        if (!previouslyAchievedAuthenticationMethods.isEmpty()) {
            return StringUtils.join(previouslyAchievedAuthenticationMethods, " ");
        }
        return null;
    }

    /**
     * Convert the object given into a {@link Collection} instead.
     * @param obj the object to convert into a collection
     * @return The collection instance containing the object provided
     */
    @SuppressWarnings("unchecked")
    public static Set<Object> convertValueToCollection(final Object obj) {
        final Set<Object> c = new HashSet<>();

        if (obj instanceof Collection) {
            c.addAll((Collection<Object>) obj);
        } else if (obj instanceof Map) {
            throw new UnsupportedOperationException(Map.class.getCanonicalName() + " is not supoorted");
        } else if (obj.getClass().isArray()) {
            for (final Object object : (Object[]) obj) {
                c.add(object);
            }
        } else {
            c.add(obj);
        }
        return c;
    }

    /**
     * Retrieves the collection of authentication methods available in the list
     * of authentication attributes. The authentication attribute that refers to the set of methods satisfied is
     * by the name of  {@link MultiFactorAuthenticationSupportingWebApplicationService#CONST_PARAM_AUTHN_METHOD}.
     *
     * @param authentication the authentication that houses the methods.
     * @return collection of fulfilled authentication methods
     */
    public static Set<String> getSatisfiedAuthenticationMethods(final Authentication authentication) {
        if (authentication.getAttributes().containsKey(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD)) {
            final Object methods = authentication.getAttributes().get(
                    MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD);
            if (methods != null) {
                final Set<Object> valuesAsACollection = convertValueToCollection(methods);
                return new HashSet<>(Arrays.asList(valuesAsACollection.toArray(new String[]{})));
            }
        }
        return Collections.emptySet();
    }


    /**
     * Gets authentication from assertionfinal.
     *
     * @param assertion the assertion
     * @return the authentication from assertionfinal
     */
    public static Authentication getAuthenticationFromAssertion(final Assertion assertion) {
        final List<Authentication> chainedAuthentications = assertion.getChainedAuthentications();
        if (!chainedAuthentications.isEmpty()) {
            final int index = chainedAuthentications.size() - 1;
            return chainedAuthentications.get(index);
        }
        return null;
    }
}
