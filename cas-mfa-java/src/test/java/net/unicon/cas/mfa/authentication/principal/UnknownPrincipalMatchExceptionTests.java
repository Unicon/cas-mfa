package net.unicon.cas.mfa.authentication.principal;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(JUnit4.class)
public class UnknownPrincipalMatchExceptionTests {

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
}
