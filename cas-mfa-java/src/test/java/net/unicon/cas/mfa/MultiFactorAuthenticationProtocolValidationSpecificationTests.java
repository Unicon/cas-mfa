package net.unicon.cas.mfa;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Map;

import net.unicon.cas.mfa.ticket.UnacceptableMultiFactorAuthenticationMethodException;
import net.unicon.cas.mfa.ticket.UnrecognizedMultiFactorAuthenticationMethodException;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.validation.Assertion;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.Mockito.*;

@RunWith(JUnit4.class)
public class MultiFactorAuthenticationProtocolValidationSpecificationTests {

    @Mock
    private Assertion assertion;

    @Mock
    private Authentication authentication;

    private final MultiFactorAuthenticationProtocolValidationSpecification spec;

    public MultiFactorAuthenticationProtocolValidationSpecificationTests() {
        MockitoAnnotations.initMocks(this);

        List<Authentication> list = mock(List.class);
        when(list.size()).thenReturn(1);

        when(this.assertion.getChainedAuthentications()).thenReturn(list);
        when(list.get(anyInt())).thenReturn(this.authentication);
        final Map<String, Object> map = mock(Map.class);
        when(authentication.getAttributes()).thenReturn(map);

        this.spec = new MultiFactorAuthenticationProtocolValidationSpecification();
    }

    @Test
    public void testDefaultSpec() {
        when(authentication.getAttributes().get(any(String.class))).thenReturn(null);
        spec.setAuthenticationMethod(null);
        assertTrue(this.spec.isSatisfiedBy(this.assertion));
    }

    @Test
    public void testValidSpecWithAuthnMethods() {
        when(authentication.getAttributes().get(any(String.class))).thenReturn("strong_two_factor");
        spec.setAuthenticationMethod("strong_two_factor");
        assertTrue(this.spec.isSatisfiedBy(this.assertion));
    }

    @Test(expected = UnacceptableMultiFactorAuthenticationMethodException.class)
    public void testUnacceptedSpec() {
        when(authentication.getAttributes().get(any(String.class))).thenReturn(null);
        spec.setAuthenticationMethod("strong_two_factor");
    }

    @Test(expected = UnrecognizedMultiFactorAuthenticationMethodException.class)
    public void testUnrecognizedSpec() {
        when(authentication.getAttributes().get(any(String.class))).thenReturn("strong_two_factor");
        spec.setAuthenticationMethod("weak_two_factor");
    }
}
