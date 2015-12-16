package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.support.DefaultMultiFactorAuthenticationSupportingWebApplicationService;
import net.unicon.cas.mfa.web.support.UnrecognizedAuthenticationMethodException;
import org.jasig.cas.authentication.principal.Response;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.Map;


import static org.junit.Assert.*;

/**
 * Created by jgasper on 5/18/15.
 */
public class RegexAuthenticationMethodTranslatorTests {

    @Test
    public void testBasicTranslate() {
        final Map<String, String> testMap = getLookupMap();

        final RegexAuthenticationMethodTranslator regexAuthenticationMethodTranslator = new RegexAuthenticationMethodTranslator(testMap);
        assertEquals("mfa1", regexAuthenticationMethodTranslator.translate(null, "CN=Staff,OU=Groups,DC=example,DC=edu"));
        assertEquals("mfa2", regexAuthenticationMethodTranslator.translate(null, "CN=Students,OU=Groups,DC=example,DC=edu"));
        assertEquals("mfa3", regexAuthenticationMethodTranslator.translate(null, "CN=Others,OU=Groups,DC=example,DC=edu"));
    }

    @Test
    public void testDefaultMfa() {
        final Map<String, String> testMap = getLookupMap();

        final String result = "duo-strong";

        final RegexAuthenticationMethodTranslator regexAuthenticationMethodTranslator = new RegexAuthenticationMethodTranslator(testMap, result);
        assertEquals(result, regexAuthenticationMethodTranslator.translate(null, "CN=sudoers,OU=AdminGroups,DC=example,DC=edu"));
    }

    @Test(expected = UnrecognizedAuthenticationMethodException.class)
    public void testTranslateException() {
        final DefaultMultiFactorAuthenticationSupportingWebApplicationService svc =
                new DefaultMultiFactorAuthenticationSupportingWebApplicationService("https://www.github.com",
                        "https://www.github.com", null, Response.ResponseType.REDIRECT, "test_authn_method");

        final Map<String, String> testMap = getLookupMap();

        final RegexAuthenticationMethodTranslator regexAuthenticationMethodTranslator = new RegexAuthenticationMethodTranslator(testMap);
        regexAuthenticationMethodTranslator.translate(svc, "CN=sudoers,OU=AdminGroups,DC=example,DC=edu");
    }

    private static Map<String, String> getLookupMap() {
        final Map<String, String> testMap = new LinkedHashMap<String, String>();
        testMap.put("CN=Staff,OU=Groups,DC=example,DC=edu", "mfa1");
        testMap.put("CN=Students,OU=Groups,DC=example,DC=edu", "mfa2");
        testMap.put(".*,OU=Groups,DC=example,DC=edu", "mfa3");
        return testMap;
    }
}
