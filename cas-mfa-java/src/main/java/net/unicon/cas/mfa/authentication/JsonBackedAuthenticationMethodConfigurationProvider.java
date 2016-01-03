package net.unicon.cas.mfa.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.FileUtils;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

/**
 * Loads authentication methods and their rank from an external configuration file
 * that is expected to be JSON. The ranking of authentication methods is
 * determined by the {@link RequestedAuthenticationMethodRankingStrategy}.
 *
 * <p>Example configuration:
 * <pre><code>
 [ {
    "rank" : 1,
     "name" : "duo_two_factor"
     }, {
     "rank" : 2,
     "name" : "strong_two_factor"
     }, {
     "rank" : 3,
     "name" : "sample_two_factor"
 } ]
 * </code></pre>
 * @author Misagh Moayyed
 */
public final class JsonBackedAuthenticationMethodConfigurationProvider implements AuthenticationMethodConfigurationProvider {

    private final Set<AuthenticationMethod> authnMethods;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Instantiates a new Authentication method loader.
     * Loads supported authentication methods from
     * the specified resource.
     * @param configuration the configuration
     * @throws IOException the iO exception
     */
    public JsonBackedAuthenticationMethodConfigurationProvider(final Resource configuration) throws IOException {
        this.authnMethods = new TreeSet<>();
        final String json = FileUtils.readFileToString(configuration.getFile());
        final Set<?> set = this.objectMapper.readValue(json, Set.class);
        for (final Iterator<?> it = set.iterator(); it.hasNext();) {
            final AuthenticationMethod method = this.objectMapper.convertValue(it.next(), AuthenticationMethod.class);
            this.authnMethods.add(method);
        }
    }

    /**
     * Instantiates a new Authentication method loader.
     * Populates the supported authn methods with the given set.
     *
     * @param authnMethods the authn methods
     */
    public JsonBackedAuthenticationMethodConfigurationProvider(final Set<AuthenticationMethod> authnMethods) {
        this.authnMethods = authnMethods;
    }

    /**
     * Instantiates a new Authentication method loader.
     */
    public JsonBackedAuthenticationMethodConfigurationProvider() {
        this.authnMethods = new TreeSet<>();
    }

    /** {@inheritDoc} **/
    @Override
    public boolean containsAuthenticationMethod(final String name) {
        return getAuthenticationMethod(name) != null;
    }

    /** {@inheritDoc} **/
    @Override
    public AuthenticationMethod getAuthenticationMethod(final String name) {
        for (final Iterator<AuthenticationMethod> it = this.authnMethods.iterator(); it.hasNext();) {
            final AuthenticationMethod f = it.next();
            if (f.getName().equals(name)) {
                return f;
            }
        }
        return  null;
    }
}
