package net.unicon.cas.mfa.web.flow;

import java.util.Map;

import net.unicon.cas.addons.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.webflow.core.collection.MutableAttributeMap;
import org.springframework.webflow.core.collection.ParameterMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(JUnit4.class)
public class ValidateInitialMultiFactorAuthenticationRequestActionTests {

    private static final String TGT_ID = "TGT-1";

    private ValidateInitialMultiFactorAuthenticationRequestAction action;

    @Mock
    private RequestContext requestContext;

    @Mock
    private Authentication authentication;

    private MutableAttributeMap mockFlowScope;

    public ValidateInitialMultiFactorAuthenticationRequestActionTests() {
        MockitoAnnotations.initMocks(this);
    }

    @Before
    public void setup() {
        final AuthenticationSupport support = mock(AuthenticationSupport.class);
        when(support.getAuthenticationFrom(TGT_ID)).thenReturn(authentication);

        this.action = new ValidateInitialMultiFactorAuthenticationRequestAction(support);

        mockFlowScope = mock(MutableAttributeMap.class);
        when(requestContext.getFlowScope()).thenReturn(mockFlowScope);

        final ParameterMap requestParams = mock(ParameterMap.class);
        when(requestContext.getRequestParameters()).thenReturn(requestParams);

    }

    private void setMockTgtContextWith(final String tgt) {
        when(requestContext.getFlowScope().get(MultiFactorRequestContextUtils.CAS_TICKET_GRANTING_TICKET_ATTR_NAME)).thenReturn(tgt);
    }

    private void setMockServiceContextWith(final Service svc) {
        when(requestContext.getFlowScope().get("service")).thenReturn(svc);
    }

    /**
     * When there is no particular Service to log into (the user is just establishing a generic
     * single sign-on session), the Action should return the Event indicating the flow should proceed
     * as per normal.
     */
    @Test
    public void testMissingServiceProceedsFlowAsNormal() throws Exception {
        setMockTgtContextWith(TGT_ID);
        final Event ev = this.action.doExecute(this.requestContext);
        assertNotNull(ev);
        assertEquals(ValidateInitialMultiFactorAuthenticationRequestAction.EVENT_ID_REQUIRE_TGT, ev.getId());
    }

    /**
     * When there is no existing TGT (no existing single sign-on session), the Action should return the Event
     * indicating the flow should proceed as per normal.
     * @throws Exception would indicate test failure
     */
    @Test
    public void testMissingTgtProceedsFlowAsNormal() throws Exception {
        setMockTgtContextWith(null);
        setMockServiceContextWith(mock(MultiFactorAuthenticationSupportingWebApplicationService.class));

        final Event ev = this.action.doExecute(this.requestContext);
        assertNotNull(ev);
        assertEquals(ValidateInitialMultiFactorAuthenticationRequestAction.EVENT_ID_REQUIRE_TGT, ev.getId());
    }

    /**
     * When there is no existing TGT, but the presenting service requires a particular authentication method,
     * the Action should expose that required authentication method in flow scope.
     * @throws Exception
     */
    @Test
    public void testRequiredAuthenticationFactorExposedWhenNoTgt() throws Exception {
        setMockTgtContextWith(null);
        setMockServiceContextWith(mock(MultiFactorAuthenticationSupportingWebApplicationService.class));

        final MultiFactorAuthenticationSupportingWebApplicationService mfaSvc =
                mock(MultiFactorAuthenticationSupportingWebApplicationService.class);

        // let's say this service requires 'real_time_sms_callback' authentication
        when(mfaSvc.getAuthenticationMethod()).thenReturn("real_time_sms_callback");
        setMockServiceContextWith(mfaSvc);

        final Event ev = this.action.doExecute(this.requestContext);
        assertNotNull(ev);
        assertEquals(ValidateInitialMultiFactorAuthenticationRequestAction.EVENT_ID_REQUIRE_TGT, ev.getId());

        // verify that the Action put the authentication method into the flow scope
        verify(mockFlowScope).put("requiredAuthenticationMethod", "real_time_sms_callback");
    }

    /**
     * When the Service does not implement the interface for indicating what authentication method it requires,
     * it requires no particular authentication method and the Action should return the Event indicating the flow
     * should proceed as per normal.
     * @throws Exception would indicate test failure
     */
    @Test
    public void testServiceDoesNotIndicateRequiredAuthenticationMethod() throws Exception {
        setMockTgtContextWith(TGT_ID);
        setMockServiceContextWith(mock(WebApplicationService.class));

        final Event ev = this.action.doExecute(this.requestContext);
        assertNotNull(ev);
        assertEquals(ValidateInitialMultiFactorAuthenticationRequestAction.EVENT_ID_REQUIRE_TGT, ev.getId());
    }

    /**
     * When the service implements the interface for indicating what authentication method it requires,
     * but indicates null as its required authentication method,
     * it requires no particular authentication method and the Action should return
     * the Event indicating the flow should proceed as per normal.
     * @throws Exception would indicate test failure
     */
    @Test
    public void testMfaServiceSpecifyingNullRequiredAuthenticationMethod() throws Exception {
        setMockTgtContextWith(TGT_ID);

        // the service implements the interface but doesn't provide a value
        MultiFactorAuthenticationSupportingWebApplicationService nullReturningMockService =
                mock(MultiFactorAuthenticationSupportingWebApplicationService.class);

        when(nullReturningMockService.getAuthenticationMethod()).thenReturn(null);

        setMockServiceContextWith(nullReturningMockService);

        final Event ev = this.action.doExecute(this.requestContext);
        assertNotNull(ev);
        assertEquals(ValidateInitialMultiFactorAuthenticationRequestAction.EVENT_ID_REQUIRE_TGT, ev.getId());
    }

    /**
     * When the service implements the interface for indicating what authentication method it requires,
     * but indicates " " as its required authentication method,
     * it requires no particular authentication method and the Action should return
     * the Event indicating the flow should proceed as per normal.
     * @throws Exception would indicate test failure
     */
    @Test
    public void testMfaServiceSpecifyingBlankRequiredAuthenticationMethod() throws Exception {
        setMockTgtContextWith(TGT_ID);

        // the service implements the interface but doesn't provide a value
        MultiFactorAuthenticationSupportingWebApplicationService nullReturningMockService =
                mock(MultiFactorAuthenticationSupportingWebApplicationService.class);

        when(nullReturningMockService.getAuthenticationMethod()).thenReturn(" ");

        setMockServiceContextWith(nullReturningMockService);

        final Event ev = this.action.doExecute(this.requestContext);
        assertNotNull(ev);
        assertEquals(ValidateInitialMultiFactorAuthenticationRequestAction.EVENT_ID_REQUIRE_TGT, ev.getId());

        // verify that the Action put the authentication method into the flow scope
        verify(mockFlowScope).put("requiredAuthenticationMethod", " ");
    }

    /**
     * When a prior Authentication was via the authentication method required by the service, consider the
     * service's authentication requirement fulfilled and proceed the login flow as per normal.
     * @throws Exception would indicate test failure
     */
    @Test
    public void testPriorAuthenticationMatchingCurrentlyRequiredAuthenticationMethodProceedsFlow() throws Exception {
        final String AUTHN_METHOD = "strong_two_factor";

        setMockTgtContextWith(TGT_ID);
        final MultiFactorAuthenticationSupportingWebApplicationService mfaSvc =
                mock(MultiFactorAuthenticationSupportingWebApplicationService.class);

        when(mfaSvc.getAuthenticationMethod()).thenReturn(AUTHN_METHOD);
        setMockServiceContextWith(mfaSvc);

        final Map map = mock(Map.class);
        when(map.get(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD))
            .thenReturn(AUTHN_METHOD);

        when(authentication.getAttributes()).thenReturn(map);

        final Event ev = this.action.doExecute(this.requestContext);
        assertNotNull(ev);
        assertEquals(ValidateInitialMultiFactorAuthenticationRequestAction.EVENT_ID_REQUIRE_TGT, ev.getId());

        // verify that the Action put the authentication method into the flow scope
        verify(mockFlowScope).put("requiredAuthenticationMethod", "strong_two_factor");
    }

    /**
     * Prior authentication specifying an authentication method *not* matching the currently
     * required authentication method should return the Event indicating the flow should branch to require the
     * now-relevant authentication method.
     * @throws Exception would indicate test failure
     */
    @Test
    public void testMismatchedAuthenticationMethodsBranchesFlow() throws Exception {

        setMockTgtContextWith(TGT_ID);
        final MultiFactorAuthenticationSupportingWebApplicationService mfaSvc =
                mock(MultiFactorAuthenticationSupportingWebApplicationService.class);

        // let's say this service requires 'strong_two_factor' authentication
        when(mfaSvc.getAuthenticationMethod()).thenReturn("strong_two_factor");
        setMockServiceContextWith(mfaSvc);


        final Map map = mock(Map.class);
        when(map.get(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD))
            .thenReturn("just_take_the_user_at_his_word");

        // whereas the Authentication has a record of previously authenticating via
        // the 'just_take_the_user_at_his_word' authentication method
        when(authentication.getAttributes()).thenReturn(map);

        final Event ev = this.action.doExecute(this.requestContext);
        assertNotNull(ev);
        assertEquals(ValidateInitialMultiFactorAuthenticationRequestAction.EVENT_ID_REQUIRE_MFA, ev.getId());

        // verify that the Action put the authentication method into the flow scope
        verify(mockFlowScope).put("requiredAuthenticationMethod", "strong_two_factor");
    }
}
