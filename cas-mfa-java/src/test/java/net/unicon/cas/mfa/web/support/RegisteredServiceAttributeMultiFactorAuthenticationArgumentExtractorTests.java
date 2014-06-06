package net.unicon.cas.mfa.web.support;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.*;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.unicon.cas.addons.serviceregistry.RegisteredServiceWithAttributes;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource;

import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;
import org.jasig.cas.web.support.ArgumentExtractor;
import org.jasig.cas.web.support.CasArgumentExtractor;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

public class RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractorTests {

    private static final String CAS_SERVICE = "https://mfa.cas.edu";
    
    private static final String CAS_AUTHN_METHOD = "strong_two";
    
    private MultiFactorAuthenticationSupportingWebApplicationService getMfaService() {
        return new DefaultMultiFactorAuthenticationSupportingWebApplicationService(CAS_SERVICE, CAS_SERVICE, null, null, CAS_AUTHN_METHOD);
    }
    
    @Test
    public void testServiceWithDefaultMfaAttribute() {
        final Set<ArgumentExtractor> set = new HashSet<ArgumentExtractor>();
        set.add(new CasArgumentExtractor());
        
        final MfaWebApplicationServiceFactory factory = mock(MfaWebApplicationServiceFactory.class);
        when(factory.create(anyString(), anyString(), anyString(), anyString(), any(AuthenticationMethodSource.class)))
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
        
        final MockHttpServletRequest req = new MockHttpServletRequest();
        req.addParameter("service", CAS_SERVICE);
        final MultiFactorAuthenticationSupportingWebApplicationService webSvc =
                (MultiFactorAuthenticationSupportingWebApplicationService) extractor.extractService(req);
        assertEquals(webSvc.getAuthenticationMethod(), CAS_AUTHN_METHOD);
    }
    
    @Test
    public void testServiceWithNoAttributeValue() {
        final Set<ArgumentExtractor> set = new HashSet<ArgumentExtractor>();
        set.add(new CasArgumentExtractor());
        
        final MfaWebApplicationServiceFactory factory = mock(MfaWebApplicationServiceFactory.class);
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
        
        final MockHttpServletRequest req = new MockHttpServletRequest();
        req.addParameter("service", CAS_SERVICE);
        final MultiFactorAuthenticationSupportingWebApplicationService webSvc =
                (MultiFactorAuthenticationSupportingWebApplicationService) extractor.extractService(req);
        assertNull(webSvc);
    }
    
    @Test
    public void testServiceWithDifferentServiceType() {
        final Set<ArgumentExtractor> set = new HashSet<ArgumentExtractor>();
        set.add(new CasArgumentExtractor());
        
        final MfaWebApplicationServiceFactory factory = mock(MfaWebApplicationServiceFactory.class);
        final AuthenticationMethodVerifier verifier = mock(AuthenticationMethodVerifier.class);
        
        final RegisteredService svc = mock(RegisteredService.class);
        when(svc.getId()).thenReturn(0L);
        when(svc.getServiceId()).thenReturn(CAS_SERVICE);
        
        final ServicesManager mgmr = mock(ServicesManager.class);
        when(mgmr.findServiceBy(anyInt())).thenReturn(svc);
        when(mgmr.findServiceBy(any(Service.class))).thenReturn(svc);
        
        final RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor extractor = 
                new RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor(set, factory, mgmr, verifier);
        
        final MockHttpServletRequest req = new MockHttpServletRequest();
        req.addParameter("service", CAS_SERVICE);
        final MultiFactorAuthenticationSupportingWebApplicationService webSvc =
                (MultiFactorAuthenticationSupportingWebApplicationService) extractor.extractService(req);
        assertNull(webSvc);
    }
}
