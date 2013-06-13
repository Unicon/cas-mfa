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
                "https://www.github.com", null, null, "test_loa");
        assertEquals(svc.getLoa(), "test_loa");
        final Response res = svc.getResponse("testTicketId");
        assertNotNull(res);
        assertEquals(res.getResponseType(), Response.ResponseType.REDIRECT);
        assertEquals(res.getUrl(), "https://www.github.com?ticket=testTicketId");
    }

    @Test
    public void createMFAServiceByRequestNoService() {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final MultiFactorAuthenticationArgumentExtractor extractor = new MultiFactorAuthenticationArgumentExtractor(
                Arrays.asList("test_loa"));
        final WebApplicationService svc = extractor.extractService(request);
        assertNull(svc);
    }

    @Test
    public void createMFAServiceByRequestNoLoa() {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final MultiFactorAuthenticationArgumentExtractor extractor = new MultiFactorAuthenticationArgumentExtractor(
                Arrays.asList("test_loa"));

        when(request.getParameter("service")).thenReturn("https://www.github.com");
        final WebApplicationService svc = extractor.extractService(request);
        assertNull(svc);
    }

    @Test
    public void createMFAServiceByRequestBadLoa() {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final MultiFactorAuthenticationArgumentExtractor extractor = new MultiFactorAuthenticationArgumentExtractor(
                Arrays.asList("test_loa"));

        when(request.getParameter("service")).thenReturn("https://www.github.com");
        when(request.getParameter("loa")).thenReturn("bad_loa");
        final WebApplicationService svc = extractor.extractService(request);
        assertNull(svc);
    }

    @Test
    public void createMFAServiceByRequestSupportedLoa() {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final MultiFactorAuthenticationArgumentExtractor extractor = new MultiFactorAuthenticationArgumentExtractor(
                Arrays.asList("test_loa"));

        when(request.getParameter("service")).thenReturn("https://www.github.com");
        when(request.getParameter("loa")).thenReturn("test_loa");
        final WebApplicationService svc = extractor.extractService(request);
        assertNotNull(svc);
        final DefaultMultiFactorAuthenticationSupportingWebApplicationService mfa =
                (DefaultMultiFactorAuthenticationSupportingWebApplicationService) svc;
        assertEquals(mfa.getLoa(), "test_loa");
    }
}
