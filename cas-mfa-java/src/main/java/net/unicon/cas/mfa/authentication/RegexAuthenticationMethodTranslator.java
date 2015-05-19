package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.support.UnrecognizedAuthenticationMethodException;
import org.jasig.cas.authentication.principal.WebApplicationService;

import java.util.*;
import java.util.regex.Pattern;

/**
 * A translator that will check a list of regex patterns and return an authentication method name
 *
 * @author John Gasper
 */
public class RegexAuthenticationMethodTranslator implements AuthenticationMethodTranslator {
    private final Map<Pattern, String> translationMap;

    private boolean ignoreIfNoMatchIsFound = true;

    private String defaultMfaMethod = "";

    /**
     * Instantiates a new Regex authentication method translator.
     *
     * @param translationMap the regex/mfa method translation map
     */
    public RegexAuthenticationMethodTranslator(final Map<String, String> translationMap) {
        final Map<Pattern, String> optimizedMap = new HashMap<Pattern, String>();

        for (final String pattern : translationMap.keySet()) {
            optimizedMap.put(Pattern.compile(pattern), translationMap.get(pattern));
        }

        this.translationMap = optimizedMap;
    }

    public void setIgnoreIfNoMatchIsFound(final boolean ignoreIfNoMatchIsFound) {
        this.ignoreIfNoMatchIsFound = ignoreIfNoMatchIsFound;
    }

    public void setDefaultMfaMethod(final String defaultMfaMethod) {
        this.defaultMfaMethod = defaultMfaMethod;
    }

    @Override
    public String translate(final WebApplicationService targetService, final String triggerValue) {
        for (final Pattern pattern : translationMap.keySet()) {
            if (pattern.matcher(triggerValue).matches()) {
                return this.translationMap.get(pattern);
            }
        }

        if (this.ignoreIfNoMatchIsFound) {
            return defaultMfaMethod;
        }

        throw new UnrecognizedAuthenticationMethodException("MFA Method for " + triggerValue, targetService.getId());
    }
}
