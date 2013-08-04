package net.unicon.cas.mfa.authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import net.unicon.cas.mfa.authentication.principal.MutablePrincipal;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

@RunWith(JUnit4.class)
public class DefaultCompositeAuthenticationTests {
    private static final String PARAM_NAME = MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD;

    private final CompositeAuthentication authentication;

    public DefaultCompositeAuthenticationTests() {

        final Map map = mock(Map.class);
        final MutablePrincipal p = mock(MutablePrincipal.class);
        when(p.getId()).thenReturn("casuser");
        when(p.getAttributes()).thenReturn(map);

        final Map authnAttrs = mock(Map.class);
        this.authentication = new DefaultCompositeAuthentication(p, authnAttrs);
    }

    @Test
    public void testEmptyAuthenticationMethodAttribute() {
        final Map map = this.authentication.getAttributes();
        when(map.containsKey(any(Object.class))).thenReturn(false);
        final Collection c = this.authentication.getSatisfiedAuthenticationMethods();
        assertEquals(c.size(), 0);
    }

    @Test
    public void testSuccessfullySatisfiedValidAuthenticationMethods() {
        final Map map = this.authentication.getAttributes();
        when(map.containsKey(any(Object.class))).thenReturn(true);

        final List list = Arrays.asList("first_method", "second_method");
        when(map.get(PARAM_NAME)).thenReturn(list);

        final Collection c = this.authentication.getSatisfiedAuthenticationMethods();
        assertEquals(c.size(), 2);
    }
}
