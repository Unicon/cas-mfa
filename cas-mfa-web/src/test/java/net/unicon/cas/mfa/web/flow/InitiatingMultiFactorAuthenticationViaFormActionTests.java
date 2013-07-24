package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationManager;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.jasig.cas.web.bind.CredentialsBinder;
import org.jasig.cas.web.flow.AuthenticationViaFormAction;
import org.jasig.cas.web.support.WebUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.binding.message.MessageContext;
import org.springframework.web.util.CookieGenerator;
import org.springframework.webflow.core.collection.MutableAttributeMap;
import org.springframework.webflow.core.collection.ParameterMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * @author Misagh Moayyed
 */
@SuppressWarnings("deprecation")
@RunWith(JUnit4.class)
public class InitiatingMultiFactorAuthenticationViaFormActionTests {

    private static final String LOGIN_TICKET = "LT-1";
    private static final String TGT_ID = "TGT-1";

    private InitiatingMultiFactorAuthenticationViaFormAction action;

    @Mock
    private AuthenticationViaFormAction authViaFormAction;

    @Mock
    private CredentialsBinder binder;

    @Mock
    private CentralAuthenticationService cas;

    @Mock
    private CookieGenerator cookieGenerator;

    @Mock
    private RequestContext ctx;

    @Mock
    private MessageContext msgCtx;

    @Mock
    private AuthenticationManager manager;

    @Mock
    private Authentication authentication;

    @Before
    public void setup() throws AuthenticationException {

        MockitoAnnotations.initMocks(this);

        this.authViaFormAction.setCentralAuthenticationService(this.cas);
        this.authViaFormAction.setCredentialsBinder(this.binder);
        this.authViaFormAction.setWarnCookieGenerator(this.cookieGenerator);

        final MutableAttributeMap flowScope = mock(MutableAttributeMap.class);
        when(ctx.getFlowScope()).thenReturn(flowScope);
        when(ctx.getRequestScope()).thenReturn(flowScope);

        MultiFactorAuthenticationSupportingWebApplicationService svc = null;
        svc = mock(MultiFactorAuthenticationSupportingWebApplicationService.class);
        when(svc.getAuthenticationMethod()).thenReturn("strong_two_factor");

        when(ctx.getFlowScope().get("service")).thenReturn(svc);
        when(ctx.getFlowScope().remove("loginTicket")).thenReturn(LOGIN_TICKET);

        when(ctx.getRequestScope().get("ticketGrantingTicketId")).thenReturn(TGT_ID);
        when(ctx.getFlowScope().get("ticketGrantingTicketId")).thenReturn(TGT_ID);

        when(ctx.getRequestParameters()).thenReturn(mock(ParameterMap.class));
        when(ctx.getRequestParameters().get("lt")).thenReturn(LOGIN_TICKET);

        when(manager.authenticate(any(Credentials.class))).thenReturn(this.authentication);

        this.action = new InitiatingMultiFactorAuthenticationViaFormAction(authViaFormAction);
        this.action.setCentralAuthenticationService(this.cas);
        this.action.setCredentialsBinder(this.binder);
        this.action.setWarnCookieGenerator(this.cookieGenerator);
        this.action.setMultiFactorAuthenticationManager(manager);
    }

    @Test
    public void testBadLoginTicket() throws Exception {
        when(ctx.getRequestParameters().get("lt")).thenReturn("");
        final Credentials credentials = getCredentials();
        final Event ev = this.action.submit(this.ctx, credentials, this.msgCtx, null);
        assertNotNull(ev);
        assertEquals(ev.getId(), AbstractMultiFactorAuthenticationViaFormAction.MFA_ERROR_EVENT_ID);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBadInvalidCredentialsId() throws Exception {
        final Credentials credentials = getCredentials();
        final Event ev = this.action.submit(this.ctx, credentials, this.msgCtx, null);
        assertNotNull(ev);
        assertEquals(ev.getId(), AbstractMultiFactorAuthenticationViaFormAction.MFA_ERROR_EVENT_ID);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBadInvalidCredentials() throws Exception {
        final Event ev = this.action.submit(this.ctx, null, this.msgCtx, "someId");
        assertNotNull(ev);
        assertEquals(ev.getId(), AbstractMultiFactorAuthenticationViaFormAction.MFA_ERROR_EVENT_ID);
    }

    @Test()
    public void testSuccessfulMfaAuthentication() throws Exception {
        final Credentials credentials = getCredentials();
        final Event ev = this.action.submit(this.ctx, credentials, this.msgCtx, "id");
        assertNotNull(ev);
        final MultiFactorAuthenticationSupportingWebApplicationService svc =
                (MultiFactorAuthenticationSupportingWebApplicationService) WebUtils.getService(this.ctx);
        assertNotNull(svc);
        assertEquals(ev.getId(), AbstractMultiFactorAuthenticationViaFormAction.MFA_SUCCESS_EVENT_ID + svc.getAuthenticationMethod());
    }

    private Credentials getCredentials() {
        final UsernamePasswordCredentials c = new UsernamePasswordCredentials();
        c.setUsername("user");
        c.setPassword("psw");
        return c;
    }
}
