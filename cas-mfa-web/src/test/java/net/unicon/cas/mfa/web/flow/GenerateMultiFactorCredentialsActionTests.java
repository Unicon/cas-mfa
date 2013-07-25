package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.addons.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.webflow.core.collection.MutableAttributeMap;
import org.springframework.webflow.execution.RequestContext;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(JUnit4.class)
public class GenerateMultiFactorCredentialsActionTests {

    private static final String TGT_ID = "TGT-1";

    private GenerateMultiFactorCredentialsAction action;

    @Mock
    private RequestContext requestContext;

    @Mock
    private Authentication authentication;

    public GenerateMultiFactorCredentialsActionTests() {
        MockitoAnnotations.initMocks(this);
    }

    @Before
    public void setup() {
        this.action = new GenerateMultiFactorCredentialsAction();

        final AuthenticationSupport support = mock(AuthenticationSupport.class);
        when(support.getAuthenticationFrom(TGT_ID)).thenReturn(authentication);
        this.action.setAuthenticationSupport(support);

        final MutableAttributeMap flowScope = mock(MutableAttributeMap.class);
        when(requestContext.getFlowScope()).thenReturn(flowScope);

    }

    private void setMockAuthenticationContextWith(final Authentication auth) {
        when(requestContext.getFlowScope().get(MultiFactorRequestContextUtils.CAS_AUTHENTICATION_ATTR_NAME)).thenReturn(auth);
    }

    private void setMockTgtContextWith(final String tgt) {
        when(requestContext.getFlowScope().get(MultiFactorRequestContextUtils.CAS_TICKET_GRANTING_TICKET_ATTR_NAME)).thenReturn(tgt);
    }

    @Test(expected=NoAuthenticationContextAvailable.class)
    public void testNoAuthentication() {
        this.action.createCredentials(requestContext, getCredentials(), "usrPsw");
    }

    @Test(expected=NoAuthenticationContextAvailable.class)
    public void testNoCredentialId() {
        this.action.createCredentials(requestContext, getCredentials(), null);
    }

    @Test(expected=NoAuthenticationContextAvailable.class)
    public void testNoCredentials() {
        this.action.createCredentials(requestContext, null, "helloWorld");
    }

    @Test
    public void testAuthenticationViaContext() {
        setMockAuthenticationContextWith(authentication);
        setMockTgtContextWith(null);

        final Credentials c = getCredentials();
        final Credentials creds = this.action.createCredentials(requestContext, c, "usrPsw");

        assertTrue(creds instanceof MultiFactorCredentials);
        final MultiFactorCredentials mfaCreds = (MultiFactorCredentials) creds;

        assertEquals(mfaCreds.getChainedAuthentications().size(), 1);
        assertEquals(mfaCreds.getChainedCredentials().size(), 1);

        assertEquals(mfaCreds.getAuthentication(), authentication);
        assertEquals(mfaCreds.getCredentials(), c);
    }

    @Test
    public void testAuthenticationViaTGT() {
        setMockAuthenticationContextWith(null);
        setMockTgtContextWith(TGT_ID);

        final Credentials c = getCredentials();
        final Credentials creds = this.action.createCredentials(requestContext, c, "usrPsw");

        assertTrue(creds instanceof MultiFactorCredentials);
        final MultiFactorCredentials mfaCreds = (MultiFactorCredentials) creds;

        assertEquals(mfaCreds.getChainedAuthentications().size(), 1);
        assertEquals(mfaCreds.getChainedCredentials().size(), 1);

        assertEquals(mfaCreds.getAuthentication(), authentication);
        assertEquals(mfaCreds.getCredentials(), c);
    }

    private Credentials getCredentials() {
        final UsernamePasswordCredentials c = new UsernamePasswordCredentials();
        c.setUsername("user");
        c.setPassword("psw");
        return c;
    }
}
