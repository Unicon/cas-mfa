package net.unicon.cas.mfa.authentication;


import net.unicon.cas.addons.serviceregistry.RegisteredServiceWithAttributes;
import net.unicon.cas.mfa.web.support.DefaultMultiFactorAuthenticationSupportingWebApplicationService;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import net.unicon.cas.mfa.web.support.MultiFactorWebApplicationServiceFactory;
import org.jasig.cas.TestUtils;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.Response;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.services.ServicesManager;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

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

        final RegisteredServiceWithAttributes rswa = Mockito.mock(RegisteredServiceWithAttributes.class);
        final HashMap<String, Object> extraAttributes = new HashMap<String, Object>();
        when(rswa.getExtraAttributes()).thenReturn(extraAttributes);

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

        final RegisteredServiceWithAttributes rswa = Mockito.mock(RegisteredServiceWithAttributes.class);
        final HashMap<String, Object> extraAttributes = new HashMap<String, Object>();
        extraAttributes.put(DefaultRegisteredServiceMfaRoleProcessorImpl.AUTHN_METHOD, CAS_AUTHN_METHOD);

        final Map<String, Object> roleMap = new HashMap<String, Object>();
        // making mfa_role incomplete: roleMap.put("mfa_attribute_name", "memberOf");
        roleMap.put(DefaultRegisteredServiceMfaRoleProcessorImpl.MFA_ATTRIBUTE_PATTERN, MEMBER_OF_VALUE);

        extraAttributes.put(DefaultRegisteredServiceMfaRoleProcessorImpl.MFA_ROLE, roleMap);
        when(rswa.getExtraAttributes()).thenReturn(extraAttributes);


        final DefaultRegisteredServiceMfaRoleProcessorImpl resolver = new DefaultRegisteredServiceMfaRoleProcessorImpl(
                getMFWASF(was), getAMCP(), getServicesManager(rswa));

        final List<MultiFactorAuthenticationRequestContext> result = resolver.resolve(auth, was);
        assertNotNull(result);
        assertEquals(0, result.size());
    }

    @Test
    public void testResolveServiceWithMfaAttributesUserInRole() throws Exception {
        final WebApplicationService was = getTargetService();
        final Authentication auth = getAuthentication(true);

        final RegisteredServiceWithAttributes rswa = Mockito.mock(RegisteredServiceWithAttributes.class);
        final HashMap<String, Object> extraAttributes = new HashMap<String, Object>();
        extraAttributes.put(DefaultRegisteredServiceMfaRoleProcessorImpl.AUTHN_METHOD, CAS_AUTHN_METHOD);

        final Map<String, Object> roleMap = new HashMap<String, Object>();
        roleMap.put(DefaultRegisteredServiceMfaRoleProcessorImpl.MFA_ATTRIBUTE_NAME, MEMBER_OF);
        roleMap.put(DefaultRegisteredServiceMfaRoleProcessorImpl.MFA_ATTRIBUTE_PATTERN, MEMBER_OF_VALUE);

        extraAttributes.put(DefaultRegisteredServiceMfaRoleProcessorImpl.MFA_ROLE, roleMap);
        when(rswa.getExtraAttributes()).thenReturn(extraAttributes);


        final DefaultRegisteredServiceMfaRoleProcessorImpl resolver = new DefaultRegisteredServiceMfaRoleProcessorImpl(
                getMFWASF(was), getAMCP(), getServicesManager(rswa));

        final List<MultiFactorAuthenticationRequestContext> result = resolver.resolve(auth, was);
        assertNotNull(result);
        assertEquals(CAS_AUTHN_METHOD, result.get(0).getMfaService().getAuthenticationMethod());
    }

    @Test
    public void testResolveServiceWithMfaAttributesUserNotInRole() throws Exception {
        final WebApplicationService was = getTargetService();
        final Authentication auth = getAuthentication(false);

        final RegisteredServiceWithAttributes rswa = Mockito.mock(RegisteredServiceWithAttributes.class);
        final HashMap<String, Object> extraAttributes = new HashMap<String, Object>();
        extraAttributes.put(DefaultRegisteredServiceMfaRoleProcessorImpl.AUTHN_METHOD, CAS_AUTHN_METHOD);

        final Map<String, Object> roleMap = new HashMap<String, Object>();
        roleMap.put(DefaultRegisteredServiceMfaRoleProcessorImpl.MFA_ATTRIBUTE_NAME, MEMBER_OF);
        roleMap.put(DefaultRegisteredServiceMfaRoleProcessorImpl.MFA_ATTRIBUTE_PATTERN, MEMBER_OF_VALUE);

        extraAttributes.put(DefaultRegisteredServiceMfaRoleProcessorImpl.MFA_ROLE, roleMap);
        when(rswa.getExtraAttributes()).thenReturn(extraAttributes);


        final DefaultRegisteredServiceMfaRoleProcessorImpl resolver = new DefaultRegisteredServiceMfaRoleProcessorImpl(
                getMFWASF(was), getAMCP(), getServicesManager(rswa));

        final List<MultiFactorAuthenticationRequestContext> result = resolver.resolve(auth, was);
        assertNotNull(result);
        assertEquals(0, result.size());
    }

    private static Authentication getAuthentication(final boolean inRole) {
        final Map<String, Object> attributes = new HashMap<String, Object>();

        if (inRole) {
            attributes.put(MEMBER_OF, MEMBER_OF_VALUE);
        }

        final Principal principal = TestUtils.getPrincipal("jdoe", attributes);
        final Authentication auth = TestUtils.getAuthentication(principal);
        return auth;
    }

    @Test
    public void testResolveServiceWithOnlyAuthnMethodAttribute() throws Exception {
        final WebApplicationService was = getTargetService();
        final Authentication auth = getAuthentication(true);

        final RegisteredServiceWithAttributes rswa = Mockito.mock(RegisteredServiceWithAttributes.class);
        final HashMap<String, Object> extraAttributes = new HashMap<String, Object>();
        extraAttributes.put(DefaultRegisteredServiceMfaRoleProcessorImpl.AUTHN_METHOD, CAS_AUTHN_METHOD);
        when(rswa.getExtraAttributes()).thenReturn(extraAttributes);

        final DefaultRegisteredServiceMfaRoleProcessorImpl resolver = new DefaultRegisteredServiceMfaRoleProcessorImpl(
                getMFWASF(was), getAMCP(), getServicesManager(rswa)
);

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

    private static ServicesManager getServicesManager(final RegisteredServiceWithAttributes rswa) {
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
        when(factory.create(anyString(), anyString(), anyString(), Response.ResponseType.REDIRECT, anyString(),
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
