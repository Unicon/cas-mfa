package net.unicon.cas.mfa.web.flow;

import java.util.Map;

import net.unicon.cas.addons.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationTransactionContext;
import net.unicon.cas.mfa.authentication.OrderedMfaMethodRankingStrategy;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.Response;
import org.jasig.cas.authentication.principal.Service;
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

    private MultiFactorAuthenticationTransactionContext mfaTx =
            new MultiFactorAuthenticationTransactionContext("test service").addMfaRequest(
                    new MultiFactorAuthenticationRequestContext(
                            new MultiFactorAuthenticationSupportingWebApplicationService() {
                                @Override
                                public String getAuthenticationMethod() {
                                    return "strong_two_factor";
                                }

                                @Override
                                public AuthenticationMethodSource getAuthenticationMethodSource() {
                                    return AuthenticationMethodSource.REQUEST_PARAM;
                                }

                                @Override
                                public Response getResponse(String ticketId) {
                                    return null;
                                }

                                @Override
                                public String getArtifactId() {
                                    return null;
                                }

                                @Override
                                public void setPrincipal(Principal principal) {

                                }

                                @Override
                                public boolean logOutOfService(String sessionIdentifier) {
                                    return false;
                                }

                                @Override
                                public boolean matches(Service service) {
                                    return false;
                                }

                                @Override
                                public String getId() {
                                    return "test service";
                                }

                                @Override
                                public Map<String, Object> getAttributes() {
                                    return null;
                                }
                            }, 3));

    public ValidateInitialMultiFactorAuthenticationRequestActionTests() {
        MockitoAnnotations.initMocks(this);
    }

    @Before
    public void setup() {
        final AuthenticationSupport support = mock(AuthenticationSupport.class);
        when(support.getAuthenticationFrom(TGT_ID)).thenReturn(authentication);

        this.action = new ValidateInitialMultiFactorAuthenticationRequestAction(support, new OrderedMfaMethodRankingStrategy());

        mockFlowScope = mock(MutableAttributeMap.class);
        when(requestContext.getFlowScope()).thenReturn(mockFlowScope);
        when(requestContext.getConversationScope()).thenReturn(mockFlowScope);

        final ParameterMap requestParams = mock(ParameterMap.class);
        when(requestContext.getRequestParameters()).thenReturn(requestParams);

        /*when(requestContext.getConversationScope().get(MultiFactorAuthenticationTransactionContext.class.getSimpleName()))
                .thenReturn(mfaTx);*/

    }

    private void setMockTgtContextWith(final String tgt, final MultiFactorAuthenticationTransactionContext mfaTx) {
        when(requestContext.getFlowScope().get(MultiFactorRequestContextUtils.CAS_TICKET_GRANTING_TICKET_ATTR_NAME)).thenReturn(tgt);
        when(requestContext.getConversationScope().get(MultiFactorAuthenticationTransactionContext.class.getSimpleName()))
                .thenReturn(mfaTx);
    }

    private void setMockServiceContextWith(final Service svc) {
        when(requestContext.getFlowScope().get("service")).thenReturn(svc);
    }

    /**
     * When there is no existing mfa transaction in conversation scope the Action should return the Event
     * indicating the flow should proceed as per normal.
     */
    @Test
    public void testMissingMfaTransactionProceedsFlowAsNormal() throws Exception {
        setMockTgtContextWith(TGT_ID, null);
        final Event ev = this.action.doExecute(this.requestContext);
        assertNotNull(ev);
        assertEquals(ValidateInitialMultiFactorAuthenticationRequestAction.EVENT_ID_REQUIRE_TGT, ev.getId());
    }

    /**
     * When there is no existing TGT (no existing single sign-on session), the Action should return the Event
     * indicating the flow should proceed as per normal.
     */
    @Test
    public void testMissingTgtProceedsFlowAsNormal() throws Exception {
        setMockTgtContextWith(null, mfaTx);
        setMockServiceContextWith(mock(MultiFactorAuthenticationSupportingWebApplicationService.class));

        final Event ev = this.action.doExecute(this.requestContext);
        assertNotNull(ev);
        assertEquals(ValidateInitialMultiFactorAuthenticationRequestAction.EVENT_ID_REQUIRE_TGT, ev.getId());
    }
}
