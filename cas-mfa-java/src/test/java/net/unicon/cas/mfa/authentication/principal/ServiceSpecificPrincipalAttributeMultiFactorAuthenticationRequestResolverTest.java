package net.unicon.cas.mfa.authentication.principal;

import net.unicon.cas.addons.serviceregistry.RegisteredServiceWithAttributes;
import net.unicon.cas.mfa.authentication.AuthenticationMethod;
import net.unicon.cas.mfa.authentication.AuthenticationMethodConfigurationProvider;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext;
import net.unicon.cas.mfa.web.support.DefaultMultiFactorAuthenticationSupportingWebApplicationService;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import net.unicon.cas.mfa.web.support.MultiFactorWebApplicationServiceFactory;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.services.ServicesManager;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Created by jgasper on 5/25/15.
 */
@RunWith(MockitoJUnitRunner.class)
public class ServiceSpecificPrincipalAttributeMultiFactorAuthenticationRequestResolverTest {
    private static final String CAS_SERVICE = "https://mfa.cas.edu";

    private static final String CAS_AUTHN_METHOD = "two-factor";

    public static final String AUTHN_METHOD = "authn_method";
    public static final String MFA_ROLE = "mfa_role";
    public static final String MFA_ATTRIBUTE_PATTERN = "mfa_attribute_pattern";
    public static final String MFA_ATTRIBUTE_NAME = "mfa_attribute_name";

    public static final String MEMBER_OF = "memberOf";
    public static final String MEMBER_OF_VALUE = "cn=test";


    @Test
    public void testResolveWithoutAnyServiceMfaAttributes() throws Exception {
        WebApplicationService was = getTargetService();
        Authentication auth = getAuthentication(true);

        RegisteredServiceWithAttributes rswa = Mockito.mock(RegisteredServiceWithAttributes.class);
        HashMap<String, Object> extraAttributes = new HashMap<String, Object>();
        when(rswa.getExtraAttributes()).thenReturn(extraAttributes);

        ServiceSpecificPrincipalAttributeMultiFactorAuthenticationRequestResolver resolver
                = new ServiceSpecificPrincipalAttributeMultiFactorAuthenticationRequestResolver(
                getMFWASF(was), getAMCP(), getServicesManager(rswa)
        );

        List<MultiFactorAuthenticationRequestContext> result = resolver.resolve(auth, was);
        assertNotNull(result);
        assertEquals(0, result.size());
    }

    @Test
    public void testResolveWithoutIncompleteServiceMfaAttributes() throws Exception {
        WebApplicationService was = getTargetService();
        Authentication auth = getAuthentication(true);

        RegisteredServiceWithAttributes rswa = Mockito.mock(RegisteredServiceWithAttributes.class);
        HashMap<String, Object> extraAttributes = new HashMap<String, Object>();
        extraAttributes.put(AUTHN_METHOD, CAS_AUTHN_METHOD);

        Map<String, Object> roleMap = new HashMap<String, Object>();
        // making mfa_role incomplete: roleMap.put("mfa_attribute_name", "memberOf");
        roleMap.put(MFA_ATTRIBUTE_PATTERN, MEMBER_OF_VALUE);

        extraAttributes.put(MFA_ROLE, roleMap);
        when(rswa.getExtraAttributes()).thenReturn(extraAttributes);


        ServiceSpecificPrincipalAttributeMultiFactorAuthenticationRequestResolver resolver
                = new ServiceSpecificPrincipalAttributeMultiFactorAuthenticationRequestResolver(
                getMFWASF(was), getAMCP(), getServicesManager(rswa)
        );

        List<MultiFactorAuthenticationRequestContext> result = resolver.resolve(auth, was);
        assertNotNull(result);
        assertEquals(0, result.size());
    }

    @Test
    public void testResolveServiceWithMfaAttributesUserInRole() throws Exception {
        WebApplicationService was = getTargetService();
        Authentication auth = getAuthentication(true);

        RegisteredServiceWithAttributes rswa = Mockito.mock(RegisteredServiceWithAttributes.class);
        HashMap<String, Object> extraAttributes = new HashMap<String, Object>();
        extraAttributes.put(AUTHN_METHOD, CAS_AUTHN_METHOD);

        Map<String, Object> roleMap = new HashMap<String, Object>();
        roleMap.put(MFA_ATTRIBUTE_NAME, MEMBER_OF);
        roleMap.put(MFA_ATTRIBUTE_PATTERN, MEMBER_OF_VALUE);

        extraAttributes.put(MFA_ROLE, roleMap);
        when(rswa.getExtraAttributes()).thenReturn(extraAttributes);


        ServiceSpecificPrincipalAttributeMultiFactorAuthenticationRequestResolver resolver
                = new ServiceSpecificPrincipalAttributeMultiFactorAuthenticationRequestResolver(
                getMFWASF(was), getAMCP(), getServicesManager(rswa)
        );

        List<MultiFactorAuthenticationRequestContext> result = resolver.resolve(auth, was);
        assertNotNull(result);
        assertEquals(CAS_AUTHN_METHOD, result.get(0).getMfaService().getAuthenticationMethod());
    }

    @Test
    public void testResolveServiceWithMfaAttributesUserNotInRole() throws Exception {
        WebApplicationService was = getTargetService();
        Authentication auth = getAuthentication(false);

        RegisteredServiceWithAttributes rswa = Mockito.mock(RegisteredServiceWithAttributes.class);
        HashMap<String, Object> extraAttributes = new HashMap<String, Object>();
        extraAttributes.put(AUTHN_METHOD, CAS_AUTHN_METHOD);

        Map<String, Object> roleMap = new HashMap<String, Object>();
        roleMap.put(MFA_ATTRIBUTE_NAME, MEMBER_OF);
        roleMap.put(MFA_ATTRIBUTE_PATTERN, MEMBER_OF_VALUE);

        extraAttributes.put(MFA_ROLE, roleMap);
        when(rswa.getExtraAttributes()).thenReturn(extraAttributes);


        ServiceSpecificPrincipalAttributeMultiFactorAuthenticationRequestResolver resolver
                = new ServiceSpecificPrincipalAttributeMultiFactorAuthenticationRequestResolver(
                getMFWASF(was), getAMCP(), getServicesManager(rswa)
        );

        List<MultiFactorAuthenticationRequestContext> result = resolver.resolve(auth, was);
        assertNotNull(result);
        assertEquals(0, result.size());
    }

    @Test
    public void testResolveServiceWithOnlyAuthnMethodAttribute() throws Exception {
        WebApplicationService was = getTargetService();
        Authentication auth = getAuthentication(true);

        RegisteredServiceWithAttributes rswa = Mockito.mock(RegisteredServiceWithAttributes.class);
        HashMap<String, Object> extraAttributes = new HashMap<String, Object>();
        extraAttributes.put(AUTHN_METHOD, CAS_AUTHN_METHOD);
        when(rswa.getExtraAttributes()).thenReturn(extraAttributes);

        ServiceSpecificPrincipalAttributeMultiFactorAuthenticationRequestResolver resolver
                = new ServiceSpecificPrincipalAttributeMultiFactorAuthenticationRequestResolver(
                getMFWASF(was), getAMCP(), getServicesManager(rswa)
        );

        List<MultiFactorAuthenticationRequestContext> result = resolver.resolve(auth, was);
        assertNotNull(result);
        assertEquals(0, result.size());
    }

    private AuthenticationMethodConfigurationProvider getAMCP() {
        return new AuthenticationMethodConfigurationProvider() {
            @Override
            public boolean containsAuthenticationMethod(String name) {
                return name.equalsIgnoreCase(CAS_AUTHN_METHOD);
            }

            @Override
            public AuthenticationMethod getAuthenticationMethod(String name) {
                return new AuthenticationMethod(name, 10);
            }
        };
    }

    private ServicesManager getServicesManager(RegisteredServiceWithAttributes rswa) {
        ServicesManager testSM = Mockito.mock(ServicesManager.class);
        when(testSM.findServiceBy(any(Service.class))).thenReturn(rswa);
        return testSM;
    }

    private MultiFactorAuthenticationSupportingWebApplicationService getMfaService() {
        return new DefaultMultiFactorAuthenticationSupportingWebApplicationService(CAS_SERVICE, CAS_SERVICE, null, null, CAS_AUTHN_METHOD);
    }

    private MultiFactorWebApplicationServiceFactory getMFWASF(WebApplicationService was) {
        final MultiFactorWebApplicationServiceFactory factory = mock(MultiFactorWebApplicationServiceFactory.class);
        when(factory.create(anyString(), anyString(), anyString(), anyString(), any(MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource.class)))
                .thenReturn(getMfaService());
        return factory;
    }

    private WebApplicationService getTargetService() {
        WebApplicationService was = Mockito.mock(WebApplicationService.class);
        when(was.getId()).thenReturn(CAS_SERVICE);
        when(was.getArtifactId()).thenReturn("test");

        return was;
    }

    private Authentication getAuthentication(final boolean inRole) {
        return new Authentication() {
            @Override
            public Principal getPrincipal() {
                return new Principal() {
                    @Override
                    public String getId() {
                        return "jdoe";
                    }

                    @Override
                    public Map<String, Object> getAttributes() {
                        Map<String, Object> attributes = new HashMap<String, Object>();

                        if (inRole) {
                            attributes.put(MEMBER_OF, MEMBER_OF_VALUE);
                        }

                        return attributes;
                    }
                };
            }

            @Override
            public Date getAuthenticatedDate() {
                return new Date();
            }

            @Override
            public Map<String, Object> getAttributes() {
                return null;
            }
        };
    }


}