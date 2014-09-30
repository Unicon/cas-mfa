package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.support.UnrecognizedAuthenticationMethodException;
import org.jasig.cas.authentication.principal.WebApplicationService;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * A stub translator that receives its legend as a map. The key for the map
 * should be the set of received authentication methods, and the value is a single
 * string to define the new authentication method name.
 *
 * If no
 * @author Misagh Moayyed
 */
public class StubAuthenticationMethodTranslator implements AuthenticationMethodTranslator {
    private final Map<Set<String>, String> translationMap;

    private boolean ignoreIfNoMatchIsFound = true;

    /**
     * Instantiates a new Stub authentication method translator.
     */
    public StubAuthenticationMethodTranslator() {
        this(Collections.EMPTY_MAP);
    }

    /**
     * Instantiates a new Sutb authentication method translator.
     *
     * @param translationMap the translation map
     */
    public StubAuthenticationMethodTranslator(final Map<Set<String>, String> translationMap) {
        this.translationMap = translationMap;
    }

    public void setIgnoreIfNoMatchIsFound(final boolean ignoreIfNoMatchIsFound) {
        this.ignoreIfNoMatchIsFound = ignoreIfNoMatchIsFound;
    }

    @Override
    public String translate(final WebApplicationService targetService, final String receivedAuthenticationMethod) {
        final Set<Set<String>> keys = this.translationMap.keySet();
        for (final Set<String> keyset : keys) {
            if (keyset.contains(receivedAuthenticationMethod)) {
                return this.translationMap.get(keyset);
            }
        }

        if (this.ignoreIfNoMatchIsFound) {
            return receivedAuthenticationMethod;
        }
        throw new UnrecognizedAuthenticationMethodException(receivedAuthenticationMethod, targetService.getId());
    }
}
