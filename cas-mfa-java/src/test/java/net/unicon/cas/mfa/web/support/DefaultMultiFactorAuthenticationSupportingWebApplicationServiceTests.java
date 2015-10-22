package net.unicon.cas.mfa.web.support;

import static org.junit.Assert.*;

import org.jasig.cas.authentication.principal.Response;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class DefaultMultiFactorAuthenticationSupportingWebApplicationServiceTests {

    /**
     * Test that an instance of {@link DefaultMultiFactorAuthenticationSupportingWebApplicationService}
     * properly implements getAuthenticationMethod() and ability to get a Response to direct the user to redirect to
     * the service with a ticket.
     */
    @Test
    public void testServiceness() {
        final DefaultMultiFactorAuthenticationSupportingWebApplicationService svc =
                new DefaultMultiFactorAuthenticationSupportingWebApplicationService("https://www.github.com",
                "https://www.github.com", null, Response.ResponseType.REDIRECT,
                        null, "test_authn_method");
        assertEquals(svc.getAuthenticationMethod(), "test_authn_method");
        final Response res = svc.getResponse("testTicketId");
        assertNotNull(res);
        assertEquals(res.getResponseType(), Response.ResponseType.REDIRECT);
        assertEquals(res.getUrl(), "https://www.github.com?ticket=testTicketId");
    }

}
