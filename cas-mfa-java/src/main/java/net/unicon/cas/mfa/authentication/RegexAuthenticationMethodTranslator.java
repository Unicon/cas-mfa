package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.support.UnrecognizedAuthenticationMethodException;
import org.jasig.cas.authentication.principal.WebApplicationService;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * A translator that will check a list of regex patterns and return an authentication method name.
 *
 * @author John Gasper
 */
public class RegexAuthenticationMethodTranslator implements AuthenticationMethodTranslator {
    private final Map<Pattern, String> translationMap;

    private String defaultMfaMethod = null;

    /**
     * Instantiates a new Regex authentication method translator.
     *
     * @param translationMap the regex/mfa method translation map (maybe an ordered map)
     */
    public RegexAuthenticationMethodTranslator(final Map<String, String> translationMap) {
        this(translationMap, null);
    }

    /**
     * Instantiates a new Regex authentication method translator.
     *
     * @param translationMap the regex/mfa method translation map (maybe an ordered map)
     * @param defaultMfaMethod the default MFA merhod to use if no match is found.
     */
    public RegexAuthenticationMethodTranslator(final Map<String, String> translationMap, final String defaultMfaMethod) {
        this.defaultMfaMethod = defaultMfaMethod;

        final Map<Pattern, String> optimizedMap = new LinkedHashMap<>();

        for (final String pattern : translationMap.keySet()) {
            optimizedMap.put(Pattern.compile(pattern), translationMap.get(pattern));
        }

        this.translationMap = optimizedMap;
    }

    @Override
    public String translate(final WebApplicationService targetService, final String triggerValue) {
        for (final Pattern pattern : translationMap.keySet()) {
            if (pattern.matcher(triggerValue).matches()) {
                return this.translationMap.get(pattern);
            }
        }

        if (this.defaultMfaMethod != null) {
            return defaultMfaMethod;
        }

        throw new UnrecognizedAuthenticationMethodException(triggerValue, targetService.getId());
    }
}
