package net.unicon.cas.mfa.authentication.principal;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

import java.util.Collections;
import java.util.Map;

import org.jasig.cas.authentication.principal.Principal;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(JUnit4.class)
public class MutablePrincipalTests {

    @Mock
    private Principal principal;

    public MutablePrincipalTests() {
        MockitoAnnotations.initMocks(this);

        when(principal.getId()).thenReturn("user");

        final Map map = mock(Map.class);
        when(map.get(any(String.class))).thenReturn(Collections.singleton("attr_value"));

        when(principal.getAttributes()).thenReturn(map);
    }

    @Test
    public void testEqualityOfPrincipals() {
        final MutablePrincipal p = new MutablePrincipal("user");
        assertTrue(p.equals(this.principal));
    }

    @Test
    public void testPrincipalAttributesAreMutable() {
        final MutablePrincipal p = new MutablePrincipal("user");
        assertEquals(p.getAttributes().size(), 0);

        p.getAttributes().put("attr", "value");
        assertEquals(p.getAttributes().size(), 1);
    }
}
