## Duo security additional factor authentication subflow

`webapp-overlay-example` Maven module includes implementation of the mfa subflow which allows integration of Duo security authentication
into the overall cas-mfa based CAS instalation. This document describes components as well as configuration.

### Components

The Duo security subflow integration consists of the following components which all reside in `webapp-overlay-example` Maven module
of the `cas-mfa` project:

* Duo web Java support code (in `src/main/java/com/duosecurity/*.java`)
* Duo web JavaScript library (in `webapp/js/duo/**`)
* CAS-specific components utilizing Duo as an authentication source (in `src/main/groovy/net/unicon/cas/mfa/authentication/duo/*.groovy`)
* A JSP view with embedded Duo security iFrame and JS library wrapper (in `WEB-INF/view/jsp/default/ui/casDuoLoginView.jsp`)

### Configuration

* Sign up for Duo account, obtain the necessary API integration keys and add them to the externalized `cas.properties`:

  ```bash
  duo.api.host=
  duo.integration.key=
  duo.secret.key=
  duo.application.key=
  ```
  > NOTE: Duo application key should be generated manually and kept secret from Duo web as per Duo web documentation: 
  > https://www.duosecurity.com/docs/duoweb#1.-generate-an-akey

Please note that the components below are already preconfigured in `webapp-overlay-example`

* Add duo authentication method ranking config to `WEB-INF/spring-configuration/argumentsExtractorsConfiguration.xml`:

  ```xml
  <util:map id="supportedAuthenticationMethodsConfig">
      ...
      <entry key="duo_two_factor" value="1"/>
      ...
  </util:map>
  ```

  > NOTE: the ranking is just an arbitrary value and should be set according to local business requirements

* Modify `login-webflow.xml` to add duo subflows and appropriate transitions:

  ```xml
  <action-state id="mfaTicketGrantingTicketExistsCheck">
      ...
      <transition on="mfa_duo_two_factor" to="mfa_duo_two_factor" />
      ...
  </action-state>

  ...

  <action-state id="realSubmit">
      ...
      <transition on="mfa_duo_two_factor" to="mfa_duo_two_factor" />
      ...
  </action-state>

  ...

  <subflow-state id="mfa_duo_two_factor" subflow="mfa_duo_two_factor" parent="#mfa_parent_abstract_subflow" />

  ```

* Register duo subflow in `WEB-INF/cas-servlet.xml`:

  ```xml
  <webflow:flow-registry id="flowRegistry" flow-builder-services="builder">
      ...
      <webflow:flow-location path="/WEB-INF/subflows/mfa_duo_two_factor_webflow.xml" id="mfa_duo_two_factor"/>
  </webflow:flow-registry>
  ```
* Add Duo view mapping in `src/main/resources/default_views.properties`:

  ```
  ### Duo Two-Factor Authentication
  casDuoLoginView.(class)=org.springframework.web.servlet.view.JstlView
  casDuoLoginView.url=/WEB-INF/view/jsp/default/ui/casDuoLoginView.jsp
  ```

* Add `WEB-INF/subflows/mfa_duo_two_factor_servlet.xml`:

  ```xml
  <bean id="duo_terminatingTwoFactorAuthenticationViaFormAction"
        class="net.unicon.cas.mfa.web.flow.TerminatingMultiFactorAuthenticationViaFormAction"
        p:centralAuthenticationService-ref="mfaAwareCentralAuthenticationService"
        p:multiFactorAuthenticationManager-ref="duo_terminatingAuthenticationManager"
        c:authenticationSupport-ref="authenticationSupport"
        c:authenticationMethodVerifier-ref="authenticationMethodVerifier"
        c:multiFactorAuthenticationRequestResolver-ref="principalAttributeMfaRequestResolver"
        c:authenticationMethodRankingStrategy-ref="authenticationMethodRankingStrategy"/>

  <bean id="duo_terminatingAuthenticationManager" parent="mfaAuthenticationManager"
        p:authenticationHandlers-ref="duo_listOfTwoFactorStrongAuthenticationHandlers" />

  <util:list id="duo_listOfTwoFactorStrongAuthenticationHandlers">
      <bean class="net.unicon.cas.mfa.authentication.duo.DuoAuthenticationHandler"
            c:duoAuthenticationService-ref="duoAuthenticationService" />
  </util:list>

  <bean id="duoAuthenticationService"
        class="net.unicon.cas.mfa.authentication.duo.DuoAuthenticationService"
        c:duoIntegrationKey="${duo.integration.key}"
        c:duoSecretKey="${duo.secret.key}"
        c:duoApplicationKey="${duo.application.key}"
        c:duoApiHost="${duo.api.host}" />
  ```




* Add `WEB-INF/subflows/mfa_duo_two_factor_webflow.xml`:

  ```xml
    <flow xmlns="http://www.springframework.org/schema/webflow"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://www.springframework.org/schema/webflow
                              http://www.springframework.org/schema/webflow/spring-webflow-2.0.xsd">

        <var name="duoCredentials" class="net.unicon.cas.mfa.authentication.duo.DuoCredentials" />
        <input name="mfaCredentials" required="true"
               type="net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials" />
        <input name="mfaService" required="true"
               type="net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService" />

    <on-start>
        <evaluate expression="initialFlowSetupAction" />
        <set name="flowScope.service" value="mfaService"
             type="net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService"/>
    </on-start>

    <action-state id="generateLoginTicket">
        <evaluate expression="generateLoginTicketAction.generate(flowRequestContext)" />
        <transition on="generated" to="viewLoginFormDuo" />
    </action-state>

    <view-state id="viewLoginFormDuo" view="casDuoLoginView" model="duoCredentials">
        <binder>
            <binding property="signedDuoResponse"/>
        </binder>
        <on-entry>
            <set name="duoCredentials.username" value="mfaCredentials.principal.id"/>
            <set name="viewScope.sigRequest" value="duoAuthenticationService.generateSignedRequestToken(mfaCredentials.principal.id)" />
            <set name="viewScope.apiHost" value="duoAuthenticationService.getDuoApiHost()" />
            <set name="viewScope.commandName" value="'duoCredentials'" />
        </on-entry>
        <transition on="submit" bind="true" to="realSubmitDuo"/>

    </view-state>

    <action-state id="realSubmitDuo">
        <on-entry>
            <set name="flowScope.mfaCredentials" value="mfaCredentials"
                 type="net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials" />
        </on-entry>
        <evaluate expression="duo_terminatingTwoFactorAuthenticationViaFormAction.submit(flowRequestContext, duoCredentials,
                              messageContext, mfaCredentials.principal.id)" />
        <transition on="mfa_duo_two_factor" to="mfaSuccess" />
        <transition on="error" to="generateLoginTicket" />
        <exception-handler bean="principalMismatchExceptionHandler"/>
    </action-state>

    <end-state id="mfaSuccess" />
    <end-state id="unknownPrincipalError" />
    <end-state id="mfaUnrecognizedAuthnMethodError" />

    <global-transitions>
        <transition to="mfaUnrecognizedAuthnMethodError"
                    on-exception="net.unicon.cas.mfa.web.support.UnrecognizedAuthenticationMethodException" />
    </global-transitions>
    </flow>
  ```

### How to trigger

In order to trigger Duo factor authentication subflow, the authentication method value of `duo_two_factor` needs to be provided to CAS
via any of the current authentication method definition sources supported by cas:

* Request parameter:

  `https://example.org:8143/cas/login?service=https://www.google.com&authn_method=duo_two_factor`

* Registered service attribute:

  ```json
  ...
  {
            "id": 1,
            "serviceId": "https://www.google.com",
            "name": "GOOGLE",
            "extraAttributes": {
                "authn_method": "duo_two_factor"
            }
  }
  ...
  ```

* Authenticated principal attribute:

  ```json
  ...
  {
    "casuser":{
      "authn_method": ["duo_two_factor"]
    }
  }
  ```
