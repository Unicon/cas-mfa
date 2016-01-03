package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.addons.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.authentication.CompositeAuthentication;
import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.Credential;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.jasig.cas.authentication.principal.Principal;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.webflow.core.collection.MutableAttributeMap;
import org.springframework.webflow.definition.FlowDefinition;
import org.springframework.webflow.definition.StateDefinition;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.FlowExecutionContext;
import org.springframework.webflow.execution.FlowSession;
import org.springframework.webflow.execution.RequestContext;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

@RunWith(JUnit4.class)
public class GenerateMultiFactorCredentialsActionTests {

    private static final String TGT_ID = "TGT-1";

    private GenerateMultiFactorCredentialsAction action;

    @Mock
    private RequestContext requestContext;

    @Mock
    private CompositeAuthentication authentication;

    @Mock
    private Principal principal;

    @Mock
    private FlowExecutionContext flowExecutionContext;

    @Mock
    private FlowSession flowSession;

    @Mock
    private FlowDefinition flowDefinition;

    @Mock
    private StateDefinition stateDefinition;

    @Mock
    private MutableAttributeMap sessionFlowScope;

    public GenerateMultiFactorCredentialsActionTests() {
        MockitoAnnotations.initMocks(this);
    }

    @Before
    public void setup() {
        this.action = new GenerateMultiFactorCredentialsAction();

        final AuthenticationSupport support = mock(AuthenticationSupport.class);
        when(support.getAuthenticationFrom(TGT_ID)).thenReturn(this.authentication);
        this.action.setAuthenticationSupport(support);

        final MutableAttributeMap flowScope = mock(MutableAttributeMap.class);
        when(requestContext.getFlowScope()).thenReturn(flowScope);

        when(principal.getId()).thenReturn("user");
        when(authentication.getPrincipal()).thenReturn(this.principal);

        when(requestContext.getFlowExecutionContext()).thenReturn(this.flowExecutionContext);
        when(requestContext.getFlowExecutionContext().getActiveSession()).thenReturn(this.flowSession);
        when(requestContext.getActiveFlow()).thenReturn(this.flowDefinition);
        when(requestContext.getFlowExecutionContext().getActiveSession().getState()).thenReturn(this.stateDefinition);

        when(requestContext.getActiveFlow().getId()).thenReturn("loginWebflow");
        when(requestContext.getFlowExecutionContext().getActiveSession().getState().getId()).thenReturn("MFA");
        when(requestContext.getFlowExecutionContext().getActiveSession().getScope()).thenReturn(this.sessionFlowScope);

    }

    private void setMockAuthenticationContextWith(final Authentication auth) {
        when(requestContext.getFlowScope().get(MultiFactorRequestContextUtils.CAS_AUTHENTICATION_ATTR_NAME)).thenReturn(auth);
    }

    private void setMockTgtContextWith(final String tgt) {
        when(requestContext.getFlowScope().get(MultiFactorRequestContextUtils.CAS_TICKET_GRANTING_TICKET_ATTR_NAME)).thenReturn(tgt);
    }


    @Test(expected=NoAuthenticationContextAvailable.class)
    public void testNoAuthentication() {

        when(this.sessionFlowScope.getRequired(anyString(),
                any(UsernamePasswordCredentials.class.getClass()))).thenReturn(getCredentials());
        this.action.doExecute(this.requestContext);
    }

    @Test(expected=NoAuthenticationContextAvailable.class)
    public void testNoCredentialId() {
        when(this.sessionFlowScope.getRequired(anyString(),
                any(UsernamePasswordCredentials.class.getClass()))).thenReturn(new UsernamePasswordCredential());
        this.action.doExecute(this.requestContext);
    }

    @Test(expected=NoAuthenticationContextAvailable.class)
    public void testNoCredentials() {
        when(this.sessionFlowScope.getRequired(anyString(),
                any(UsernamePasswordCredentials.class.getClass()))).thenReturn(null);
        this.action.doExecute(this.requestContext);
    }

    @Test
    public void testAuthenticationViaContext() {
        setMockAuthenticationContextWith(authentication);
        setMockTgtContextWith(null);

        final Credential c = getCredentials();

        when(this.sessionFlowScope.getRequired(anyString(),
                any(UsernamePasswordCredentials.class.getClass()))).thenReturn(c);
        final Event event = this.action.doExecute(this.requestContext);
        final Credential creds = (Credential)
                event.getAttributes().get(GenerateMultiFactorCredentialsAction.ATTRIBUTE_ID_MFA_CREDENTIALS);

        assertTrue(creds instanceof MultiFactorCredentials);
        final MultiFactorCredentials mfaCreds = (MultiFactorCredentials) creds;

        assertEquals(mfaCreds.countChainedAuthentications(), 1);
        assertEquals(mfaCreds.getChainedCredentials().size(), 1);

        assertEquals(mfaCreds.getAuthentication().getPrincipal(), authentication.getPrincipal());
        assertEquals(mfaCreds.getCredentials(), c);
    }

    @Test
    public void testAuthenticationViaTGT() {
        setMockAuthenticationContextWith(null);
        setMockTgtContextWith(TGT_ID);

        final Credential c = getCredentials();

        when(this.sessionFlowScope.getRequired(anyString(),
                any(UsernamePasswordCredentials.class.getClass()))).thenReturn(c);
        final Event event = this.action.doExecute(this.requestContext);
        final Credential creds = (Credential)
                event.getAttributes().get(GenerateMultiFactorCredentialsAction.ATTRIBUTE_ID_MFA_CREDENTIALS);

        assertTrue(creds instanceof MultiFactorCredentials);
        final MultiFactorCredentials mfaCreds = (MultiFactorCredentials) creds;

        assertEquals(mfaCreds.countChainedAuthentications(), 1);
        assertEquals(mfaCreds.getChainedCredentials().size(), 1);

        assertEquals(mfaCreds.getAuthentication().getPrincipal(), authentication.getPrincipal());
        assertEquals(mfaCreds.getCredentials(), c);
    }

    private static Credential getCredentials() {
        final UsernamePasswordCredential c = new UsernamePasswordCredential();
        c.setUsername("user");
        c.setPassword("psw");
        return c;
    }
}
