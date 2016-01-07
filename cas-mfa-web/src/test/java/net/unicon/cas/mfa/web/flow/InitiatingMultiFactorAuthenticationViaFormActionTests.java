package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.mfa.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.authentication.AuthenticationMethod;
import net.unicon.cas.mfa.authentication.JsonBackedAuthenticationMethodConfigurationProvider;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestResolver;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationTransactionContext;
import net.unicon.cas.mfa.authentication.OrderedMultiFactorMethodRankingStrategy;
import net.unicon.cas.mfa.web.flow.event.ErroringMultiFactorAuthenticationSpringWebflowEventBuilder;
import net.unicon.cas.mfa.web.flow.event.MultiFactorAuthenticationSpringWebflowEventBuilder;
import net.unicon.cas.mfa.web.support.AuthenticationMethodVerifier;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import net.unicon.cas.mfa.web.support.MultiFactorWebApplicationServiceFactory;
import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationManager;
import org.jasig.cas.authentication.Credential;
import org.jasig.cas.authentication.UsernamePasswordCredential;
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
import org.springframework.webflow.definition.TransitionDefinition;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.util.SortedSet;
import java.util.TreeSet;

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
    private static final String AUTHN_METHOD = "strong_two_factor";

    private InitiatingMultiFactorAuthenticationViaFormAction action;

    @Mock
    private AuthenticationViaFormAction authViaFormAction;

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

    @Mock
    private MultiFactorAuthenticationRequestResolver multiFactorAuthenticationRequestResolver;

    @Mock
    private AuthenticationSupport authenticationSupport;

    @Mock
    private MultiFactorWebApplicationServiceFactory factory;

    @Mock
    private AuthenticationMethodVerifier verifier;

    @Before
    public void setup() throws Exception {

        MockitoAnnotations.initMocks(this);

        this.authViaFormAction.setCentralAuthenticationService(this.cas);
        this.authViaFormAction.setWarnCookieGenerator(this.cookieGenerator);

        final MutableAttributeMap flowScope = mock(MutableAttributeMap.class);

        when(ctx.getFlowScope()).thenReturn(flowScope);
        when(ctx.getRequestScope()).thenReturn(flowScope);
        when(ctx.getConversationScope()).thenReturn(flowScope);
        when(ctx.getMessageContext()).thenReturn(this.msgCtx);

        MultiFactorAuthenticationSupportingWebApplicationService svc = null;
        svc = mock(MultiFactorAuthenticationSupportingWebApplicationService.class);
        when(svc.getAuthenticationMethod()).thenReturn(AUTHN_METHOD);

        when(ctx.getFlowScope().get("service")).thenReturn(svc);
        when(ctx.getFlowScope().remove("loginTicket")).thenReturn(LOGIN_TICKET);

        when(ctx.getRequestScope().get("ticketGrantingTicketId")).thenReturn(TGT_ID);
        when(ctx.getFlowScope().get("ticketGrantingTicketId")).thenReturn(TGT_ID);
        when(ctx.getFlowScope().get("credentials")).thenReturn(getCredentials());

        when(ctx.getRequestParameters()).thenReturn(mock(ParameterMap.class));
        when(ctx.getRequestParameters().get("lt")).thenReturn(LOGIN_TICKET);

        when(ctx.getConversationScope().get(MultiFactorAuthenticationTransactionContext.class.getSimpleName()))
                .thenReturn(new MultiFactorAuthenticationTransactionContext("test service"));

        when(manager.authenticate(any(Credential.class))).thenReturn(this.authentication);

        final SortedSet<AuthenticationMethod> validAuthenticationMethods =
                new TreeSet<>();
        validAuthenticationMethods.add(new AuthenticationMethod("sample_two_factor", 2));
        validAuthenticationMethods.add(new AuthenticationMethod("strong_two_factor", 4));

        final JsonBackedAuthenticationMethodConfigurationProvider loader =
                new JsonBackedAuthenticationMethodConfigurationProvider(validAuthenticationMethods);

        this.action = new InitiatingMultiFactorAuthenticationViaFormAction(multiFactorAuthenticationRequestResolver,
                authenticationSupport, verifier, authViaFormAction, new OrderedMultiFactorMethodRankingStrategy(loader),
                "https://sso.school.edu");

        this.action.setCentralAuthenticationService(this.cas);
        this.action.setWarnCookieGenerator(this.cookieGenerator);
        this.action.setMultiFactorAuthenticationManager(manager);
    }


    @Test
    public void testBadLoginTicket() throws Exception {
        when(ctx.getRequestParameters().get("lt")).thenReturn("");

        final Event ev = this.action.doExecute(ctx);
        assertNotNull(ev);
        assertEquals(ev.getId(), ErroringMultiFactorAuthenticationSpringWebflowEventBuilder.MFA_ERROR_EVENT_ID);
    }

    @Test
    public void testBadInvalidCredentials() throws Exception {
        when(ctx.getFlowScope().get("credentials")).thenReturn(null);
        final Event ev = this.action.doExecute(this.ctx);
        assertNotNull(ev);

        assertEquals(ev.getId(), ErroringMultiFactorAuthenticationSpringWebflowEventBuilder.MFA_ERROR_EVENT_ID);
    }

    @Test
    public void testSuccessfulMfaAuthentication() throws Exception {
        final String id = MultiFactorAuthenticationSpringWebflowEventBuilder.MFA_EVENT_ID_PREFIX
                + AUTHN_METHOD;
        final TransitionDefinition def = mock(TransitionDefinition.class);
        when(def.getId()).thenReturn(id);

        when(this.ctx.getMatchingTransition(anyString())).thenReturn(def);

        final Event ev = this.action.doExecute(this.ctx);
        assertNotNull(ev);
        final MultiFactorAuthenticationSupportingWebApplicationService svc =
                (MultiFactorAuthenticationSupportingWebApplicationService) WebUtils.getService(this.ctx);
        assertNotNull(svc);

        assertEquals(ev.getId(), id);
    }

    private static Credential getCredentials() {
        final UsernamePasswordCredential c = new UsernamePasswordCredential();
        c.setUsername("user");
        c.setPassword("psw");
        return c;
    }
}
