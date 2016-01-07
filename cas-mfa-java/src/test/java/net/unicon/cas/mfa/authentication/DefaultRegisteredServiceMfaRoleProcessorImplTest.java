package net.unicon.cas.mfa.authentication;


import net.unicon.cas.mfa.web.support.DefaultMultiFactorAuthenticationSupportingWebApplicationService;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import net.unicon.cas.mfa.web.support.MultiFactorWebApplicationServiceFactory;
import org.jasig.cas.TestUtils;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.Response;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.services.DefaultRegisteredServiceProperty;
import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Created by jgasper on 5/25/15.
 */
@RunWith(MockitoJUnitRunner.class)
public class DefaultRegisteredServiceMfaRoleProcessorImplTest {
    private static final String CAS_SERVICE = "https://mfa.cas.edu";

    private static final String CAS_AUTHN_METHOD = "two-factor";

    public static final String MEMBER_OF = "memberOf";
    public static final String MEMBER_OF_VALUE = "cn=test";


    @Test
    public void testResolveWithoutAnyServiceMfaAttributes() throws Exception {
        final WebApplicationService was = getTargetService();
        final Authentication auth = getAuthentication(true);

        final RegisteredService rswa = TestUtils.getRegisteredService("test1");
        final DefaultRegisteredServiceMfaRoleProcessorImpl resolver = new DefaultRegisteredServiceMfaRoleProcessorImpl(
            getMFWASF(was), getAMCP(), getServicesManager(rswa));

        final List<MultiFactorAuthenticationRequestContext> result = resolver.resolve(auth, was);
        assertNotNull(result);
        assertEquals(0, result.size());
    }

    @Test
    public void testResolveWithoutIncompleteServiceMfaAttributes() throws Exception {
        final WebApplicationService was = getTargetService();
        final Authentication auth = getAuthentication(true);

        final RegisteredService rswa = TestUtils.getRegisteredService("test1");

        DefaultRegisteredServiceProperty prop = new DefaultRegisteredServiceProperty();
        prop.setValues(Collections.singleton(CAS_AUTHN_METHOD));
        rswa.getProperties().put(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD, prop);

        prop = new DefaultRegisteredServiceProperty();
        prop.setValues(Collections.singleton(MEMBER_OF_VALUE));
        rswa.getProperties().put(RegisteredServiceMfaRoleProcessor.MFA_ATTRIBUTE_PATTERN, prop);

        final DefaultRegisteredServiceMfaRoleProcessorImpl resolver = new DefaultRegisteredServiceMfaRoleProcessorImpl(
                getMFWASF(was), getAMCP(), getServicesManager(rswa));

        final List<MultiFactorAuthenticationRequestContext> result = resolver.resolve(auth, was);
        assertNotNull(result);
        assertEquals(0, result.size());
    }


    private static Authentication getAuthentication(final boolean inRole) {
        final Map<String, Object> attributes = new HashMap<>();

        if (inRole) {
            attributes.put(MEMBER_OF, MEMBER_OF_VALUE);
        }

        final Principal principal = TestUtils.getPrincipal("jdoe", attributes);
        final Authentication auth = TestUtils.getAuthentication(principal);
        return auth;
    }


    @Test
    public void testResolveServiceWithMfaAttributesUserInRole() throws Exception {
        final WebApplicationService was = getTargetService();
        final Authentication auth = getAuthentication(true);


        final RegisteredService rswa = TestUtils.getRegisteredService("test1");

        DefaultRegisteredServiceProperty prop = new DefaultRegisteredServiceProperty();
        prop.setValues(Collections.singleton(CAS_AUTHN_METHOD));
        rswa.getProperties().put(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD, prop);

        prop = new DefaultRegisteredServiceProperty();
        prop.setValues(Collections.singleton(MEMBER_OF));
        rswa.getProperties().put(RegisteredServiceMfaRoleProcessor.MFA_ATTRIBUTE_NAME, prop);

        prop = new DefaultRegisteredServiceProperty();
        prop.setValues(Collections.singleton(MEMBER_OF_VALUE));
        rswa.getProperties().put(RegisteredServiceMfaRoleProcessor.MFA_ATTRIBUTE_PATTERN, prop);

        final DefaultRegisteredServiceMfaRoleProcessorImpl resolver = new DefaultRegisteredServiceMfaRoleProcessorImpl(
                getMFWASF(was), getAMCP(), getServicesManager(rswa));

        final List<MultiFactorAuthenticationRequestContext> result = resolver.resolve(auth, was);
        assertNotNull(result);
        assertEquals(CAS_AUTHN_METHOD, result.get(0).getMfaService().getAuthenticationMethod());
    }

    @Test
    public void testResolveServiceWithOnlyAuthnMethodAttribute() throws Exception {
        final WebApplicationService was = getTargetService();
        final Authentication auth = getAuthentication(true);

        final RegisteredService rswa = TestUtils.getRegisteredService("test1");

        final DefaultRegisteredServiceProperty prop = new DefaultRegisteredServiceProperty();
        prop.setValues(Collections.singleton(CAS_AUTHN_METHOD));
        rswa.getProperties().put(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD, prop);

        final DefaultRegisteredServiceMfaRoleProcessorImpl resolver = new DefaultRegisteredServiceMfaRoleProcessorImpl(
                getMFWASF(was), getAMCP(), getServicesManager(rswa));

        final List<MultiFactorAuthenticationRequestContext> result = resolver.resolve(auth, was);
        assertNotNull(result);
        assertEquals(0, result.size());
    }

    private static AuthenticationMethodConfigurationProvider getAMCP() {
        return new AuthenticationMethodConfigurationProvider() {
            @Override
            public boolean containsAuthenticationMethod(final String name) {
                return name.equalsIgnoreCase(CAS_AUTHN_METHOD);
            }

            @Override
            public AuthenticationMethod getAuthenticationMethod(final String name) {
                return new AuthenticationMethod(name, 10);
            }
        };
    }

    private static ServicesManager getServicesManager(final RegisteredService rswa) {
        final ServicesManager testSM = Mockito.mock(ServicesManager.class);
        when(testSM.findServiceBy(any(Service.class))).thenReturn(rswa);
        return testSM;
    }

    private static MultiFactorAuthenticationSupportingWebApplicationService getMfaService() {
        return new DefaultMultiFactorAuthenticationSupportingWebApplicationService(CAS_SERVICE, CAS_SERVICE, null,
                Response.ResponseType.REDIRECT, CAS_AUTHN_METHOD);
    }

    private static MultiFactorWebApplicationServiceFactory getMFWASF(final WebApplicationService was) {
        final MultiFactorWebApplicationServiceFactory factory = mock(MultiFactorWebApplicationServiceFactory.class);
        when(factory.create(anyString(), anyString(), anyString(), any(Response.ResponseType.class), anyString(),
                any(MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource.class)))
                .thenReturn(getMfaService());
        return factory;
    }

    private static WebApplicationService getTargetService() {
        final WebApplicationService was = Mockito.mock(WebApplicationService.class);
        when(was.getId()).thenReturn(CAS_SERVICE);
        when(was.getArtifactId()).thenReturn("test");

        return was;
    }



}
