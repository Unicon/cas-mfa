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

The `requireTgt` case is uninteresting: the CAS login flow proceeds as normal.

### multiFactorAuthentication login flow state

The `requireMfa` case is interesting: the flow proceeds to the `multiFactorAuthentication` state.  This is a Spring Web Flow subflow-state:

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




TODO: and models this as a specification.

Of course this just amounts to a UI hint, since a nefarious end-user could edit the login URL to adjust the parameter so as to not require the alternative login path.

TODO: new sessions vs existing sessions


## Remembering how users authenticated

In order to appropriately handle existing sessions and in order to be able to include the authentication method in the validation response, the CAS server needs to remember how the user authenticated.

TODO: how is this implemented?


## Including Authentication Method in the Validation Response and Enforcing


# Functional analysis

Another way to think through this code is to consider the use cases and how they are implemented.

## Service specifies no particular authentication method

## Service specifies an authentication method; new session

## Service specifies an authentication method; existing sufficient session

## Service specifies an authentication method; existing insufficient session

## Validation doesn't match login




# Guidance for extension

## Adding an additional authentication method

TODO


## Modeling service authentication method requirements in the services registry rather than as a request parameter

TODO
