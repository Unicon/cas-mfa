package net.unicon.cas.mfa.web.support;

import net.unicon.cas.mfa.authentication.RegisteredServiceMfaRoleProcessor;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource;
import org.jasig.cas.TestUtils;
import org.jasig.cas.authentication.principal.Response;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.services.DefaultRegisteredServiceProperty;
import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;
import org.jasig.cas.web.support.ArgumentExtractor;
import org.jasig.cas.web.support.CasArgumentExtractor;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
        final List<ArgumentExtractor> set = new ArrayList<>();
        set.add(new CasArgumentExtractor());
        
        final MultiFactorWebApplicationServiceFactory factory = mock(MultiFactorWebApplicationServiceFactory.class);
        when(factory.create(anyString(), anyString(), anyString(), any(Response.ResponseType.class),
                anyString(), any(AuthenticationMethodSource.class)))
            .thenReturn(getMfaService());
        
        final AuthenticationMethodVerifier verifier = mock(AuthenticationMethodVerifier.class);

        final RegisteredService svc = TestUtils.getRegisteredService(CAS_SERVICE);
        final DefaultRegisteredServiceProperty prop = new DefaultRegisteredServiceProperty();
        prop.setValues(Collections.singleton(CAS_AUTHN_METHOD));
        svc.getProperties().put(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD, prop);
        
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
        final List<ArgumentExtractor> set = new ArrayList<>();
        set.add(new CasArgumentExtractor());
        
        final MultiFactorWebApplicationServiceFactory factory = mock(MultiFactorWebApplicationServiceFactory.class);
        final AuthenticationMethodVerifier verifier = mock(AuthenticationMethodVerifier.class);

        final RegisteredService svc = TestUtils.getRegisteredService(CAS_SERVICE);
        final DefaultRegisteredServiceProperty prop = new DefaultRegisteredServiceProperty();
        svc.getProperties().put(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD, prop);
        
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
        final List<ArgumentExtractor> set = new ArrayList<>();
        set.add(new CasArgumentExtractor());

        final MultiFactorWebApplicationServiceFactory factory = mock(MultiFactorWebApplicationServiceFactory.class);
        when(factory.create(anyString(), anyString(), anyString(), any(Response.ResponseType.class),
                anyString(), any(AuthenticationMethodSource.class)))
                .thenReturn(getMfaService());

        final AuthenticationMethodVerifier verifier = mock(AuthenticationMethodVerifier.class);

        final RegisteredService svc = TestUtils.getRegisteredService(CAS_SERVICE);
        DefaultRegisteredServiceProperty prop = new DefaultRegisteredServiceProperty();
        prop.setValues(Collections.singleton(CAS_AUTHN_METHOD));
        svc.getProperties().put(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD, prop);

        prop = new DefaultRegisteredServiceProperty();
        svc.getProperties().put(RegisteredServiceMfaRoleProcessor.MFA_ATTRIBUTE_NAME, prop);

        prop = new DefaultRegisteredServiceProperty();
        prop.setValues(Collections.singleton(CAS_AUTHN_METHOD));
        svc.getProperties().put(RegisteredServiceMfaRoleProcessor.MFA_ATTRIBUTE_PATTERN, prop);

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
        final List<ArgumentExtractor> set = new ArrayList<>();
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
