WORK IN PROGRESS.  NOT YET COMPLETE.

# Target audience

The target audience for this page is CAS community members seeking to understand the architecture and makeup of this CAS server extension.

This is not the guide for locally implementing.


# Scope

This document narrates the architecture of the customizations in this project.

This document lives in `cas-mfa-web` because its scope is the customizations the web components depend upon and the web components themselves.

# The Big Picture

Whereas this project is about enabling multifactor authentication, the architecture and customizations are more about enabling and enforcing services opting into alternative branches of the CAS login web flow than particularly about multifactor authentication as such.

CAS-using applications supply an authentication method hint on their redirect to CAS login as an `authn_method` request parameter, akin to the `renew` and `gateway` parameters traditionally available in CAS.

CAS remenbers how the user authenticated.

CAS includes the authentication mechanism in a customized ticket validation response and enforces a parameter-specified authentication method on ticket validation.

# A components analysis

One way to understand this project is to review the components and how they interact, how control flows through them.  This section reviews in this way.


## Detecting CAS-using services requiring alternative authentication mechanisms

CAS-using services indicate to CAS that they require an alternative login flow via an additional `authn_method` request parameter on login.

In CAS server architecture terms, the parameter on login is an "argument" to CAS that needs to be "extracted" from the request.  The CAS server normally uses a `CasArgumentExtractor` to extract arguments afforded by the traditional CAS protocol.  This project adds a `MultiFactorAuthenticationArgumentExtractor` (declared in  `argumentExtractorsConfiguration.xml` ) to extract the optional directed authentication method parameter and constrain it to the set of known supported authentication method names.

The fundamental purpose of argument extractors are to generate Service objects representing the CAS-using service the end user is trying to log in to.  The `MultiFactorAuthenticationArgumentExtractor` generates a `MultiFactorAuthenticationSupportingWebApplicationService` .  These are like regular CAS `WebApplicationService`s except they know what authentication method the service has required.

## Honoring alternative authentication requirements in the login experience

### mfaTicketGrantingTicketExistsCheck login flow state

The `login-webflow.xml` is customized to start with a new inserted action state, namely,

    <action-state id="mfaTicketGrantingTicketExistsCheck">
        <evaluate expression="validateInitialMfaRequestAction" />
        <transition on="requireMfa" to="multiFactorAuthentication" />
        <transition on="requireTgt" to="ticketGrantingTicketExistsCheck" />
    </action-state>

The `validateInitialMfaRequestAction` is defined in `mfa-servlet.xml` as

    <bean id="validateInitialMfaRequestAction"
        class="net.unicon.cas.mfa.web.flow.ValidateInitialMultiFactorAuthenticationRequestAction"
        c:authSupport-ref="authenticationSupport" />


This custom action considers the authentication method required by the CAS-using service the user is attempting to log in to, if any, and compares this to the recorded method of how the user authenticated previously in the active single sign-on session, if any, and makes a binary decision about whether the login flow should proceeed as per normal (the `requireTgt` event) or whether the flow should branch (the `requireMfa` event) to enforce an as-yet unfulfilled authentication method requirement expressed by the CAS-using service.

This Action branches to `requireMfa` only if the user has an existing single sign-on session that does not yet meet the authentication method requirements.  If the requirements are already met *or if the user hasn't logged in at all* the Action signals to proceed the flow.  This is so that the user will first complete the normal user and password login process before (later, through another flow action) branching to then experience and fulfill the additional authentication factor requirement.

### multiFactorAuthentication login flow state

In the `requireMfa` case, the flow proceeds to the `multiFactorAuthentication` state.  This is a Spring Web Flow subflow-state:

    <subflow-state id="multiFactorAuthentication" subflow="mfa">
        <on-entry>
            <evaluate expression="generateMfaCredentialsAction.createCredentials(flowRequestContext, credentials, credentials.username)"/>
        </on-entry>

        <input name="mfaCredentials" value="flowScope.mfaCredentials" required="true"
               type="net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials" />
        <transition on="mfaSuccess" to="sendTicketGrantingTicket" />
        <transition on="mfaError" to="generateLoginTicket" />
    </subflow-state>

On entering the state, the flow invokes `generateMfaCredentialsAction.createCredentials()`.

`generateMfaCredentialsAction` is defined in `mfa-servlet.xml`

    <!-- Generate and chain multifactor credentials based on current authenticated credentials. -->
    <bean id="generateMfaCredentialsAction" class="net.unicon.cas.mfa.web.flow.GenerateMultiFactorCredentialsAction"
        p:authenticationSupport-ref="authenticationSupport"/>

This simply reads or instantiates a MultiFactoCredentials instance to back the one-time-password form.

This is a sub-flow action with `subflow="mfa"`, so it branches control to the `mfa-webflow.xml` subflow.

### mfa-webflow.xml subflow

This sub-flow is a typical Spring Web Flow rendering and handling the submission of a form, here to collect the additional one-time password credentials making up the additional authentication factor to achieve multi (two) factor authentication.

It uses the `loginTicket` technique of the typical CAS username and password login form to discourage form replay and it follows the standard CAS login flow pattern separating the form rendering and submit-processing flow states.

The additional credential is currently modeled as an additional username and password credential.

Submitting the form actuates `terminatingTwoFactorAuthenticationViaFormAction.doBind(flowRequestContext, flowScope.credentials)`

Like other flow actions, this is defined in `mfa-servlet.xml`:

    <bean id="terminatingTwoFactorAuthenticationViaFormAction"
        class="net.unicon.cas.mfa.web.flow.TerminatingMultiFactorAuthenticationViaFormAction"
        p:centralAuthenticationService-ref="mfaAwareCentralAuthenticationService"
        p:multiFactorAuthenticationManager-ref="terminatingAuthenticationManager" />

`TerminatingMultiFactorAuthenticationViaFormAction` `doBind()` "binds" the submitted form to CAS concepts of Credentials.

Subsequently, `submit()` actually authenticates the credentials.

The flow can end in successful authentication of the additional credential or in error.

### Returning from the sub-flow

Back in the main login-webflow, completing the mfa subflow yields

    <subflow-state id="multiFactorAuthentication" subflow="mfa">
        <on-entry>
            <evaluate expression="generateMfaCredentialsAction.createCredentials(flowRequestContext, credentials, credentials.username)"/>
        </on-entry>

        <input name="mfaCredentials" value="flowScope.mfaCredentials" required="true"
               type="net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials" />
        <transition on="mfaSuccess" to="sendTicketGrantingTicket" />
        <transition on="mfaError" to="generateLoginTicket" />
    </subflow-state>


Success in fulfilling the authentication method requirement modeled in the sub-flow leads to sending the ticket granting ticket down to the browser.

Error in the sub-flow sends the user back to the generate login ticket step in the flow.


### Branching to multi-factor authentication after traditional authentication

Recall that back in `mfaTicketGrantingTicketExistsCheck` there were two options: `requireMfa` and `requireTgt`.  The above treated in some detail the `requireMfa` case arising when an existing single sign-on session is insufficient.  Howver, the `requireTgt` normal login flow path proceeded in *both* the case where no particular unfulfilled authentication method is required *and* in the case where a particular authentication method is required but the branching needs deferred to later after the traditional login form.

Therefore, the processing of the regular username and password login form needs to include an additional check after the form to determine if branching to the sub-flow is then appropriate.

This happens in the main login flow's `realSubmit`

    <action-state id="realSubmit">
      <evaluate expression="initiatingAuthenticationViaFormAction.submit(flowRequestContext,
         flowScope.credentials, messageContext, flowScope.credentials.username)" />
         <transition on="warn" to="warn" />
         <transition on="success" to="sendTicketGrantingTicket" />
         <transition on="error" to="generateLoginTicket" />
         <transition on="mfaSuccess" to="multiFactorAuthentication" />
    	</action-state>

Note that `mfaSuccess` leads to that same `multiFactorAuthentication` sub-flow.


## Remembering how users authenticated

In order to appropriately handle existing sessions and in order to be able to include the authentication method in the validation response, the CAS server needs to remember how the user authenticated.

This is implemented as metadata on the Authentication.

The Terminating... Action chains the new Multifactor authentication onto the prior Authentication and packages this into a new Ticket Granting Ticket.

    private Event createTicketGrantingTicket(final Authentication authentication, final RequestContext context,
            final Credentials credentials, final MessageContext messageContext, final String id) {
        ...
            final MultiFactorCredentials mfa = MultiFactorRequestContextUtils.getMfaCredentials(context);

            mfa.getChainedAuthentications().add(authentication);
            mfa.getChainedCredentials().put(id, credentials);

            MultiFactorRequestContextUtils.setMfaCredentials(context, mfa);
            WebUtils.putTicketGrantingTicketInRequestScope(context, this.cas.createTicketGrantingTicket(mfa));
            return getSuccessEvent();
        ...
    }



## Including Authentication Method in the Validation Response and Enforcing

This project customizes the traditional CAS server XML ticket validation responses to include the authentication method.  This allows CAS-using sevices to predicate behavior on or apply access control rules on how the user authenticated.

CAS-using applications can also communicate their authentication method requirement to the CAS server on their ticket validation request and rely on the CAS server to enforce the expressed authentication method requirements.

### Including the authentication method in the ticket validation response

The `casServiceValidate.jsp` is customized to include

        <c:if test="${not empty authn_method}">
          <cas:authn_method>${authn_method}</cas:authn_method>
        </c:if>
      </c:if>
    </cas:authenticationSuccess>

A customized `MultiFactorServiceValidateController` places the `authn_method` attribute into the model available to the JSP for rendering:

    ...
    final int index = assertion.getChainedAuthentications().size() - 1;
    final Authentication authToUse = assertion.getChainedAuthentications().get(index);

    final String authnMethodUsed = (String) authToUse.getAttributes()
      .get(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD);
    if (authnMethodUsed != null) {
      success.addObject(MODEL_AUTHN_METHOD, authnMethodUsed);
    }
    ...



### Enforcing a CAS-using-service-indicated required authentication method

In CAS, criteria as to whether a given ticket meets a given service's validation requirements are modeled as Specifications.

Traditionally, CAS-using applications can specifiy "renew=true" on a validation request, which causes the Specification to require that the ticket include a fresh underlying Authentication.  Likewise, CAS-using applications can and should use the `/serviceValidate` rather than `/proxyValidate` ticket validation endpoint whenever possible, with the `/serviceValidate` endpoint rejecting all proxy tickets.  That `/serviceValidate` requirement against proxy chains is also modeled as a Specification.

A service's epxressed requirement for a particular authentication method is likewise modeled as a Specification, with the customized MultiFactorServiceValidateController manually binding the "authn_method" request parameter into a `MultiFactorAuthenticationProtocolValidationSpecification` and then asking that specification whether the available Assertion fulfills it.

The Specifiation implementation is a little goofy in using runtime exceptions to characterize how the assertion does not match since the API would have afforded only true or false.




### `/proxyValidate` unmofified

These customizations do not modify proxy ticket validation.

TODO: modify proxy ticket validation



# Functional analysis

Another way to think through this code is to consider the use cases and how they are implemented.

## Service specifies no particular authentication method

When a service specifies no particular authentication method on /cas/login, the CAS server behaves exactly as per normal, as if it weren't customized.

The `mfaTicketGrantingTicketExistsCheck` continues the flow as per normal when there's no particular authentication method requirement specified, regardless of whether there's an existing ticket granting ticket or not.

If the normal flow involves prompting for the normal username and password, the Action handling that form submission
returns the normal `success` transition continuing the flow per normal.

The only thing different between customized CAS and un-customized CAS in this case is that on `/cas/serviceValidate`, if the service doesn't specify a required `authn_method`, CAS will require no particular such method, but it will communicate the method fulfilled in the ticket validation response.


## Service specifies an authentication method; new session

When an `authn_method` parameter on `/cas/login` advises a required authentication method and the user does not yet have a valid single sign-on session, customized CAS proceeds the login flow per normal in the `mfaTicketGrantingTicketExistsCheck` but branches the flow to provide the additional authentication method prompt in the customized handling of the normal username and password form submission.

The result of this flow is to require both authentication factors: the traditional username and password, and the additional factor reqiuired in the sub-flow.


## Service specifies an authentication method; existing sufficient session

When an `authn_method` parameter on `/cas/login` advises a required authentication method and the user already has a valid single sign-on session fulfilling that authentication method requirement, customized CAS proceeds the login flow per normal in the `mfaTicketGrantingTicketExistsCheck` which leads to exercising the existing valid ticket granting ticket to issue a service ticket as per normal without user interaction.


## Service specifies an authentication method; existing insufficient session

When an `authn_method` parameter on `/cas/login` advises a required authentication method and the user already has a valid single sign-on session that does not fulfill this particular authentication method requirement, customized CAS branches the login flow in the `mfaTicketGrantingTicketExistsCheck` to provide the additional authentication method prompt.

The result of this flow is to consider the prior completion of the normal username and password prompt sufficient but to require require augmentation by providing the additional factor reqiuired in the sub-flow.

## Validation doesn't match login

The `authn_method` parameter on login is merely advisory, a hint to allow CAS to provide an appropriate login experience.  Enforcement of the authentication method requirement happens entirely on the `/cas/serviceValidate` ticket validation, optionally enforced in a coarse-grained way at the CAS server by CAS's requiring fulfillment of an `authn_method` expressed via request parameter, and in any case including the authentication method in the ticket validation response.


# Guidance for extension

This architecture is intended for extensibility in at least a couple of directions: adopters and others who work from this code should be able to add additinoal authentication methods and should be able to change the strategy for how CAS understands what authentication method is required for which services.

## Adding an additional authentication method

Currently, adding an additional authentication method would involve modification to `mfaTicketGrantingTicketExistsCheck` and both at the web flow and the Java layer, to add handling for additional `authn_method` values, modification to the customized handling of the traditional username and password login form submission to appropriately branch to the multiple authentication-method-specific sub-flows.

## Modeling service authentication method requirements in the services registry rather than as a request parameter

The shortest path to modeling service authentication method requirements in the service registry rather than or in addition to indication of these requirements via request parameter would be through adjustment of the

# Design Decisions and Tradeoffs

## Authentication methods are sub-flows

Authentication methods are, concretely, required nonstandard sub-flows within the login web flow.  A custom `authn_method` value could be associated with any behavior that can be expressed as a sub-flow.  This is essentially un-limited as regards the sub-flow (sub-flows can include pretty much any behavior Web applications are capable of) and importantly limiting as regards the main flow (branching to the sub-flow happens at specific points, and the behavior of the main flow is otherwise unmodified.)

In practice this means that authentication methods that amount to *additional* behavior above and beyond the traditional behavior are enabled and methods that would outright replace the traditional username and password prompt are not enabled in this architecture.

Of course, particular adopters are free to adjust the main web flow further to introduce other behavior at that layer, thereby enabling authentication method behaviors not supported by the "additional behavior modeled in the sub-flow" architecture.

## Authentication methods are unordered identifiers

There is no ordering, hierarchy, dependency, or other relationship among custom authn_methods.  While conceptually "really_strong_two_factor" might fulfill "strong_two_factor", the architecture has no direct way of modeling and reflecting that conceptual relationship, though interestingly a "strong_two_factor" sub-flow could in its implementation consider evidence of a prior "really_strong_two_factor" authentication and return control to the main flow without requiring user interaction.

The short version of this is that interesting relationships among authentication methods are feasible to implement, but are not modeled in metadata or handled by the infrastructure.
