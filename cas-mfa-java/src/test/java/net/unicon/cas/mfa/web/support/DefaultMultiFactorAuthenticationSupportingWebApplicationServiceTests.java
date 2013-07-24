package net.unicon.cas.mfa.web.support;

import static org.junit.Assert.*;

import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;

import org.jasig.cas.authentication.principal.Response;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import static org.mockito.Mockito.*;

@RunWith(JUnit4.class)
public class DefaultMultiFactorAuthenticationSupportingWebApplicationServiceTests {

    @Test
    public void createNewMFAService() {
        final DefaultMultiFactorAuthenticationSupportingWebApplicationService svc =
                new DefaultMultiFactorAuthenticationSupportingWebApplicationService("https://www.github.com",
                "https://www.github.com", null, null, "test_authn_method");
        assertEquals(svc.getAuthenticationMethod(), "test_authn_method");
        final Response res = svc.getResponse("testTicketId");
        assertNotNull(res);
        assertEquals(res.getResponseType(), Response.ResponseType.REDIRECT);
        assertEquals(res.getUrl(), "https://www.github.com?ticket=testTicketId");
    }

    @Test
    public void createMFAServiceByRequestSupportedAuthnMethod() {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final MultiFactorAuthenticationArgumentExtractor extractor = new MultiFactorAuthenticationArgumentExtractor(
                Arrays.asList("test_authn_method"));

        when(request.getParameter("service")).thenReturn("https://www.github.com");
        when(request.getParameter("authn_method")).thenReturn("test_authn_method");
        final WebApplicationService svc = extractor.extractService(request);
        assertNotNull(svc);
        final DefaultMultiFactorAuthenticationSupportingWebApplicationService mfa =
                (DefaultMultiFactorAuthenticationSupportingWebApplicationService) svc;
        assertEquals(mfa.getAuthenticationMethod(), "test_authn_method");
    }
}
