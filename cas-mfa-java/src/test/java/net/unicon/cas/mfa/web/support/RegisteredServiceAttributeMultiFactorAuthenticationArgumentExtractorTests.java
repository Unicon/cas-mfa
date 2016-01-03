package net.unicon.cas.mfa.web.support;

import net.unicon.cas.addons.serviceregistry.RegisteredServiceWithAttributes;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource;
import org.jasig.cas.authentication.principal.Response;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;
import org.jasig.cas.web.support.ArgumentExtractor;
import org.jasig.cas.web.support.CasArgumentExtractor;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;


public class RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractorTests {

    private static final String CAS_SERVICE = "https://mfa.cas.edu";
    
    private static final String CAS_AUTHN_METHOD = "strong_two";
    
    private static MultiFactorAuthenticationSupportingWebApplicationService getMfaService() {
        return new DefaultMultiFactorAuthenticationSupportingWebApplicationService(CAS_SERVICE, CAS_SERVICE, null,
                Response.ResponseType.REDIRECT, CAS_AUTHN_METHOD);
    }
    
    private static HttpServletRequest getRequest() {
        final HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter(anyString())).thenReturn(CAS_SERVICE);
        return req;
        
    }
    
    @Test
    public void testServiceWithDefaultMfaAttribute() {
        final List<ArgumentExtractor> set = new ArrayList<ArgumentExtractor>();
        set.add(new CasArgumentExtractor());
        
        final MultiFactorWebApplicationServiceFactory factory = mock(MultiFactorWebApplicationServiceFactory.class);
        when(factory.create(anyString(), anyString(), anyString(), any(Response.ResponseType.class),
                anyString(), any(AuthenticationMethodSource.class)))
            .thenReturn(getMfaService());
        
        final AuthenticationMethodVerifier verifier = mock(AuthenticationMethodVerifier.class);
        
        final Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD, CAS_AUTHN_METHOD);
        
        final RegisteredServiceWithAttributes svc = mock(RegisteredServiceWithAttributes.class);
        when(svc.getId()).thenReturn(0L);
        when(svc.getServiceId()).thenReturn(CAS_SERVICE);
        when(svc.getExtraAttributes()).thenReturn(attrs);
        
        final ServicesManager mgmr = mock(ServicesManager.class);
        when(mgmr.findServiceBy(anyInt())).thenReturn(svc);
        when(mgmr.findServiceBy(any(Service.class))).thenReturn(svc);
        
        final RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor extractor = 
                new RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor(set, factory, mgmr, verifier);

        final MultiFactorAuthenticationSupportingWebApplicationService webSvc =
                (MultiFactorAuthenticationSupportingWebApplicationService) extractor.extractService(getRequest());
        assertNotNull(webSvc);
        assertEquals(webSvc.getAuthenticationMethod(), CAS_AUTHN_METHOD);
    }
    
    @Test
    public void testServiceWithNoAttributeValue() {
        final List<ArgumentExtractor> set = new ArrayList<ArgumentExtractor>();
        set.add(new CasArgumentExtractor());
        
        final MultiFactorWebApplicationServiceFactory factory = mock(MultiFactorWebApplicationServiceFactory.class);
        final AuthenticationMethodVerifier verifier = mock(AuthenticationMethodVerifier.class);
        
        final Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD, "");
        
        final RegisteredServiceWithAttributes svc = mock(RegisteredServiceWithAttributes.class);
        when(svc.getId()).thenReturn(0L);
        when(svc.getServiceId()).thenReturn(CAS_SERVICE);
        when(svc.getExtraAttributes()).thenReturn(attrs);
        
        final ServicesManager mgmr = mock(ServicesManager.class);
        when(mgmr.findServiceBy(anyInt())).thenReturn(svc);
        when(mgmr.findServiceBy(any(Service.class))).thenReturn(svc);
        
        final RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor extractor = 
                new RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor(set, factory, mgmr, verifier);
        
        final MultiFactorAuthenticationSupportingWebApplicationService webSvc =
                (MultiFactorAuthenticationSupportingWebApplicationService) extractor.extractService(getRequest());
        assertNull(webSvc);
    }

    @Test
    public void testServiceWithMfaRole() {
        final List<ArgumentExtractor> set = new ArrayList<ArgumentExtractor>();
        set.add(new CasArgumentExtractor());

        final MultiFactorWebApplicationServiceFactory factory = mock(MultiFactorWebApplicationServiceFactory.class);
        when(factory.create(anyString(), anyString(), anyString(), any(Response.ResponseType.class),
                anyString(), any(AuthenticationMethodSource.class)))
                .thenReturn(getMfaService());

        final AuthenticationMethodVerifier verifier = mock(AuthenticationMethodVerifier.class);

        final Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD, CAS_AUTHN_METHOD);
        attrs.put("mfa_role", new HashMap<String, Object>());

        final RegisteredServiceWithAttributes svc = mock(RegisteredServiceWithAttributes.class);
        when(svc.getId()).thenReturn(0L);
        when(svc.getServiceId()).thenReturn(CAS_SERVICE);
        when(svc.getExtraAttributes()).thenReturn(attrs);

        final ServicesManager mgmr = mock(ServicesManager.class);
        when(mgmr.findServiceBy(anyInt())).thenReturn(svc);
        when(mgmr.findServiceBy(any(Service.class))).thenReturn(svc);

        final RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor extractor =
                new RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor(set, factory, mgmr, verifier);

        final MultiFactorAuthenticationSupportingWebApplicationService webSvc =
                (MultiFactorAuthenticationSupportingWebApplicationService) extractor.extractService(getRequest());
        assertNull(webSvc);
    }

    @Test
    public void testServiceWithDifferentServiceType() {
        final List<ArgumentExtractor> set = new ArrayList<ArgumentExtractor>();
        set.add(new CasArgumentExtractor());
        
        final MultiFactorWebApplicationServiceFactory factory = mock(MultiFactorWebApplicationServiceFactory.class);
        final AuthenticationMethodVerifier verifier = mock(AuthenticationMethodVerifier.class);
        
        final RegisteredService svc = mock(RegisteredService.class);
        when(svc.getId()).thenReturn(0L);
        when(svc.getServiceId()).thenReturn(CAS_SERVICE);
        
        final ServicesManager mgmr = mock(ServicesManager.class);
        when(mgmr.findServiceBy(anyInt())).thenReturn(svc);
        when(mgmr.findServiceBy(any(Service.class))).thenReturn(svc);
        
        final RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor extractor = 
                new RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor(set, factory, mgmr, verifier);

        final MultiFactorAuthenticationSupportingWebApplicationService webSvc =
                (MultiFactorAuthenticationSupportingWebApplicationService) extractor.extractService(getRequest());
        assertNull(webSvc);
    }
}
