package net.unicon.cas.mfa.web.support;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(JUnit4.class)
public class MultiFactorAuthenticationArgumentExtractorTests {

    @Test
    public void testUnidentifiedMfaService() {
        final List<String> emptyList = Collections.emptyList();
        final MultiFactorAuthenticationArgumentExtractor extractor = new MultiFactorAuthenticationArgumentExtractor(emptyList);

        final HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter("service")).thenReturn("https://www.github.com");
        when(request.getParameter(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD))
                .thenReturn("test_loa");

        assertNull(extractor.extractService(request));
    }

    @Test
    public void testValidMfaService() {
        final List<String> emptyList = Arrays.asList("strong_two_factor");
        final MultiFactorAuthenticationArgumentExtractor extractor = new MultiFactorAuthenticationArgumentExtractor(emptyList);

        final HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter("service")).thenReturn("https://www.github.com");
        when(request.getParameter(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD))
                .thenReturn("strong_two_factor");

        assertTrue(extractor.extractService(request) instanceof MultiFactorAuthenticationSupportingWebApplicationService);
    }
}
