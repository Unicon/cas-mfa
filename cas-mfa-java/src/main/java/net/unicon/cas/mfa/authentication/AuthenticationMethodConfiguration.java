package net.unicon.cas.mfa.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.FileUtils;
import org.springframework.core.io.Resource;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

/**
 * @author Misagh Moayyed
 */
public final class AuthenticationMethodConfiguration {

    private final Set<AuthenticationMethod> authnMethods;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Instantiates a new Authentication method loader.
     * Loads supported authentication methods from
     * the specified resource.
     * @param configuration the configuration
     * @throws IOException the iO exception
     */
    public AuthenticationMethodConfiguration(final Resource configuration) throws IOException {
        this.authnMethods = new TreeSet<AuthenticationMethod>();
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
    public AuthenticationMethodConfiguration(final Set<AuthenticationMethod> authnMethods) {
        this.authnMethods = authnMethods;
    }

    /**
     * Instantiates a new Authentication method loader.
     */
    public AuthenticationMethodConfiguration() {
        this.authnMethods = new TreeSet<AuthenticationMethod>();
    }

    /**
     * Contains authentication method.
     *
     * @param name the name
     * @return true if the method is found
     */
    public boolean containsAuthenticationMethod(final String name) {
        return getAuthenticationMethod(name) != null;
    }

    /**
     * Gets authentication method.
     *
     * @param name the name
     * @return the authentication method, or null if none is found.
     */
    public AuthenticationMethod getAuthenticationMethod(final String name) {
        for (final Iterator<AuthenticationMethod> it = this.authnMethods.iterator(); it.hasNext();) {
            final AuthenticationMethod f = it.next();
            if (f.getName().equals(name)) {
                return f;
            }
        }
        return  null;
    }

    /**
     * Main void.
     *
     * @param agrs the agrs
     * @throws Exception the exception
     */
    public static void main(final String[] agrs) throws Exception {
        final File f = new File("c:\\etc\\cas\\authn-methods.conf");
        final String s = FileUtils.readFileToString(f);

        final HashSet<AuthenticationMethod> ss = new HashSet<AuthenticationMethod>();
        ss.add(new AuthenticationMethod("m", 1));
        ss.add(new AuthenticationMethod("m1", 12));
        new ObjectMapper().writerWithDefaultPrettyPrinter().writeValue(f, ss);

        final Set<?> aa = new ObjectMapper().readValue(FileUtils.readFileToString(f), Set.class);

    }
}
