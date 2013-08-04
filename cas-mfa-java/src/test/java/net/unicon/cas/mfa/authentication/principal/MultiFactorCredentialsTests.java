package net.unicon.cas.mfa.authentication.principal;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(JUnit4.class)
public class MultiFactorCredentialsTests {

    @Test(expected = UnknownPrincipalMatchException.class)
    public void testMultifactorMismatchedPrincipals() {

        final Principal firstPrincipal = new SimplePrincipal("casuser");

        final Authentication firstAuthentication = mock(Authentication.class);
        when(firstAuthentication.getPrincipal()).thenReturn(firstPrincipal);

        final Principal secondPrincipal = new SimplePrincipal("antheruser");

        final Authentication secondAuthentication = mock(Authentication.class);
        when(secondAuthentication.getPrincipal()).thenReturn(secondPrincipal);

        final MultiFactorCredentials c = new MultiFactorCredentials();
        c.addAuthenticationToChain(firstAuthentication);
        c.addAuthenticationToChain(secondAuthentication);
    }

    @Test
    public void testMultifactorAddMatchingCredentials() {
        final Principal firstPrincipal = new SimplePrincipal("casuser");

        final Authentication firstAuthentication = mock(Authentication.class);
        when(firstAuthentication.getPrincipal()).thenReturn(firstPrincipal);

        final Principal secondPrincipal = new SimplePrincipal("casuser");

        final Authentication secondAuthentication = mock(Authentication.class);
        when(secondAuthentication.getPrincipal()).thenReturn(secondPrincipal);

        final MultiFactorCredentials c = new MultiFactorCredentials();
        c.addAuthenticationToChain(firstAuthentication);
        c.addAuthenticationToChain(secondAuthentication);
        assertEquals(2, c.countChainedAuthentications());
    }

    @Test
    public void testCompositeAuthenticationAndPrincipalAttributes() {
        final Map attributes1 = new HashMap();
        attributes1.put("attr1", "attr2");
        attributes1.put("uid", "username");

        final Principal firstPrincipal = new SimplePrincipal("casuser", attributes1);

        final Authentication firstAuthentication = mock(Authentication.class);
        when(firstAuthentication.getPrincipal()).thenReturn(firstPrincipal);
        when(firstAuthentication.getAttributes())
            .thenReturn(Collections.singletonMap(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD,
                    (Object) "first_method"));

        final Map attributes2 = new HashMap();
        attributes2.put("attr1", "attr3");
        attributes2.put("cn", "commonName");

        final Principal secondPrincipal = new SimplePrincipal("casuser", attributes2);

        final Authentication secondAuthentication = mock(Authentication.class);
        when(secondAuthentication.getPrincipal()).thenReturn(secondPrincipal);
        when(secondAuthentication.getAttributes())
            .thenReturn(Collections.singletonMap(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD,
                (Object) "second_method"));

        final MultiFactorCredentials c = new MultiFactorCredentials();
        c.addAuthenticationToChain(firstAuthentication);
        c.addAuthenticationToChain(secondAuthentication);
        assertEquals(2, c.countChainedAuthentications());

        final Authentication authn = c.getAuthentication();
        assertTrue(authn.getPrincipal().equals(firstPrincipal));
        assertTrue(authn.getPrincipal().equals(secondPrincipal));

        final Principal thePrincipal = authn.getPrincipal();
        assertEquals(thePrincipal.getAttributes().size(), 3);

        assertTrue(thePrincipal.getAttributes().containsKey("attr1"));
        assertTrue(thePrincipal.getAttributes().containsKey("uid"));
        assertTrue(thePrincipal.getAttributes().containsKey("cn"));
        assertEquals(thePrincipal.getAttributes().get("attr1"), "attr3");

        assertEquals(authn.getAttributes().size(), 1);

        final Set set = new HashSet(Arrays.asList("first_method", "second_method"));
        assertEquals(authn.getAttributes().get(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD),
                set);
    }
}
