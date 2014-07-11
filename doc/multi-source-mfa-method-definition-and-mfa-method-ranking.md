## Configuration components

This document describes configuration of the beans representing components for the newly introduced
multi-source mfa method definitions (request param, registered service, principal attribute) and
new mfa method ranking mechanism.

### mfa methods ranking config

The smaller numerical value represents higher ranking

```xml
<util:map id="supportedAuthenticationMethodsConfig">
    <entry key="strong_two_factor" value="1"/>
    <entry key="sample_two_factor" value="2"/>
</util:map>
```

### Supporting strategy APIs implementations (AuthenticationMethodVerifier, MfaWebApplicationServiceFactory)

```xml
<bean id="authenticationMethodVerifier" class="net.unicon.cas.mfa.web.support.DefaultAuthenticationMethodVerifier"
      c:supportedAuthenticationMethods-ref="supportedAuthenticationMethodsConfig"/>

<bean id="mfaServiceFactory" class="net.unicon.cas.mfa.web.support.DefaultMfaWebApplicationServiceFactory"
      c:httpClient-ref="noRedirectHttpClient"
      c:disableSingleSignOut="${slo.callbacks.disabled:true}"/>
```

### Target argument extractors for request param and registered service source mfa definitions

```xml
<bean id="requestParamMfaArgumentExtractor" parent="mfaArgumentExtractor"
      class="net.unicon.cas.mfa.web.support.RequestParameterMultiFactorAuthenticationArgumentExtractor"/>

<bean id="registeredServiceAttributeMfaArgumentExtractor" parent="mfaArgumentExtractor"
      class="net.unicon.cas.mfa.web.support.RegisteredServiceAttributeMultiFactorAuthenticationArgumentExtractor"
      c:servicesManager-ref="servicesManager" />
```

### Wrapper argument extractor delegating to the target ones and collecting all the mfa requests into an mfa transaction

The collected mfa requests get the ranking number based on the configured `supportedAuthenticationMethodsConfig` map at runtime.

```xml
<util:set id="mfaArgumentExtractors">
    <ref bean="registeredServiceAttributeMfaArgumentExtractor"/>
    <ref bean="requestParamMfaArgumentExtractor"/>
</util:set>

<bean id="mfaRequestsCollectingArgumentExtractor"
      class="net.unicon.cas.mfa.web.support.MultiFactorAuthenticationRequestsCollectingArgumentExtractor"
      c:mfaArgumentExstractors-ref="mfaArgumentExtractors"
      c:mfaRankingConfig-ref="supportedAuthenticationMethodsConfig"/>
```

### mfa request resolver implementation that creates an mfa request based on the principal attribute after primary authentication leg

If authenticated principal configured attribute is the source for mfa method definition, the mfa request is created
and either added to the current existing mfa transaction or a new mfa transaction is created if no other mfa request sources
have requested an mfa. A created mfa request gets the ranking number based on the configured `supportedAuthenticationMethodsConfig` map at runtime.

```xml
<bean id="principalAttributeMfaRequestResolver"
      class="net.unicon.cas.mfa.authentication.principal.PrincipalAttributeMultiFactorAuthenticationRequestResolver"
      c:mfaMethodAttributeName="${mfa.method.userAttribute:authn_method}"
      c:mfaServiceFactory-ref="mfaServiceFactory"
      c:mfaRankingConfig-ref="supportedAuthenticationMethodsConfig"/>
```

### mfa method ranking strategy default implementation and components using it

```xml
<bean id="authenticationMethodRankingStrategy" class="net.unicon.cas.mfa.authentication.OrderedMfaMethodRankingStrategy"/>

<bean id="initiatingAuthenticationViaFormAction"
          class="net.unicon.cas.mfa.web.flow.InitiatingMultiFactorAuthenticationViaFormAction"
          c:wrapperAuthenticationAction-ref="authenticationViaFormAction"
          c:multiFactorAuthenticationRequestResolver-ref="principalAttributeMfaRequestResolver"
          c:authenticationSupport-ref="authenticationSupport"
          c:authenticationMethodVerifier-ref="authenticationMethodVerifier"
          p:centralAuthenticationService-ref="centralAuthenticationService"          
          p:warnCookieGenerator-ref="warnCookieGenerator"
          p:multiFactorAuthenticationManager-ref="mfaAuthenticationManager"
          
          <!-- mfa method ranking API -->
          c:authenticationMethodRankingStrategy-ref="authenticationMethodRankingStrategy"/>
          
<bean id="terminatingTwoFactorAuthenticationViaFormAction"
        class="net.unicon.cas.mfa.web.flow.TerminatingMultiFactorAuthenticationViaFormAction" 
        p:centralAuthenticationService-ref="mfaAwareCentralAuthenticationService"
        p:multiFactorAuthenticationManager-ref="terminatingAuthenticationManager"
        c:authenticationSupport-ref="authenticationSupport"
        c:authenticationMethodVerifier-ref="authenticationMethodVerifier"
        c:multiFactorAuthenticationRequestResolver-ref="principalAttributeMfaRequestResolver"
        
        <!-- mfa method ranking API -->
        c:authenticationMethodRankingStrategy-ref="authenticationMethodRankingStrategy"/>
                  
<bean id="validateInitialMfaRequestAction"
          class="net.unicon.cas.mfa.web.flow.ValidateInitialMultiFactorAuthenticationRequestAction"
          c:authSupport-ref="authenticationSupport"
          
          <!-- mfa method ranking API -->
          c:authenticationMethodRankingStrategy-ref="authenticationMethodRankingStrategy"/>                  
```