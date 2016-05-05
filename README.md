## What is this project?  [![Maven Central](https://maven-badges.herokuapp.com/maven-central/net.unicon/cas-mfa/badge.svg?style=flat)](https://maven-badges.herokuapp.com/maven-central/net.unicon/cas-mfa)

[![Gitter](https://badges.gitter.im/Join Chat.svg)](https://gitter.im/Unicon/cas-mfa?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

This is a project to develop free and open source compatibly licensed extensions for the CAS server `v4.1.x` product implementing

* support for authenticating using multiple authentication factors
* support for relying parties (CAS-using applications) understanding how strongly the user authenticated from the 
ticket validation response, and
* support for relying parties exerting authentication strength requirements.

### NOTICE

*Minimum supported version of CAS in versions is `4.1.x`. MFA integration with CAS `3.x` as part of this project is NO LONGER supported or maintained, as CAS `v3.x` itself is EOLed.*

## Requirements
* JDK 7+
* Apache Maven 3.3.x
* CAS 4.1.x

## MultiFactor Support
* `duo-two-factor` (via DuoSecurity)

## Build Status
* [![Build Status](https://secure.travis-ci.org/Unicon/cas-mfa.png)](http://travis-ci.org/Unicon/cas-mfa)
* [ ![Codeship Status for Unicon/cas-mfa](https://www.codeship.io/projects/0bbd72d0-b74c-0130-d193-1eff452fc99e/status?branch=master)](https://www.codeship.io/projects/4315)


## Configuration

### Maven Overlay
Use [the following maven overlay](https://github.com/Unicon/cas-mfa/blob/master/cas-mfa-overlay/pom.xml) as an example.

### AuthN Methods
An `authn-methods.conf` file is expected to be found at `/etc/cas` with the following content:

```json
[ {
  "rank" : 1,
  "name" : "duo-two-factor"
} ]

```

### Messages
The following UI messages should be put into `messages.properties` file:

```properties
# Multifactor Authentication Messages
UNACCEPTABLE_AUTHENTICATION_METHOD=Ticket ''{0}'' did not fulfill the required authentication method ''{1}''.
UNRECOGNIZED_AUTHENTICATION_METHOD=This CAS server does not recognize the authentication method [''{0}''] specified on the validation request.
service.mfa.unrecognized.authn.method.header=Unrecognized Authentication Method
service.mfa.unrecognized.authn.method.message=You are trying to log in to <strong>''{0}''</strong> with a required authentication method of <strong>''{1}''</strong>. \
Unfortunately, CAS doesn't recognize that authentication method and so does not know how to require you to authenticate in that way.
service.mfa.service.requires.mfa.header=This service requires a specific authentication method in addition to username and password.
service.mfa.service.requires.mfa.message=The additional required authentication method is [''{0}'']. After successfully providing username and password, you will be prompted for this additional authentication factor.
service.mfa.service.mfa.inprogress.header=Multifactor Authentication is in progress...
service.mfa.service.mfa.inprogress.message=The additional required authentication method is [''{0}'']. The authentication is requested by [''{1}''].
screen.mfa.welcome.instructions=Enter your one-time password
screen.mfa.button.cancel=Not you?
screen.mfa.welcome.back=Welcome back, {0}!
service.mfa.unknown.principal.header=User not recognized
service.mfa.unknown.principal.message=CAS cannot establish an authentication context because it doesn't recognize one or more of the \
provided credentials. It is likely that the newly provided credentials are resolved in such a way that do not match at least one of the \
authenticated user ids (otherwise known as the 'Principal').

service.mfa.generic.error.heading=An authentication error has occurred!
service.mfa.generic.error.message=Additional information: {0}
```

### Properties
The following settings are required for MFA in `cas.properties`:

```properties
# mfa.method.userAttribute=
# mfa.destroy.prev.sso=
# mfa.default.authn.method=
# mfa.authn.methods.config.location=
# mfa.method.response.attribute=

duo.api.host=
duo.integration.key=
duo.secret.key=
duo.application.key=
```

### Per Application
Services that wish to declare their authentication method, must do so inside 
the service registry configuration. 

```json
{
  "@class" : "org.jasig.cas.services.RegexRegisteredService",
  "serviceId" : "^https://.*",
  "properties" : {
    "@class" : "java.util.HashMap",
    "authn_method" : {
      "@class" : "org.jasig.cas.services.DefaultRegisteredServiceProperty",
      "values" : [ "java.util.HashSet", [ "duo-two-factor" ] ]
    }
  }
}

```
### Per Attribute

CAS may aso initiate the sequence for a desired authentication method based on a configured principal attribute. Upon successful 
authentication, the principal attributes that are constructed by CAS will be queried for the given attribute. 
Its value will route the login flow to execute the appropriate authentication level.

```json
mfa.method.userAttribute=memberOf
```

The attribute value should be `duo-two-factor`.

### Per Application & Attribute
Activates MFA for a given application, only if the authenticated user carries
an attribute that matches the given pattern.

```json
{
  "@class" : "org.jasig.cas.services.RegexRegisteredService",
  "serviceId" : "^https://.*",
  "properties" : {
    "@class" : "java.util.HashMap",
    "authn_method" : {
      "@class" : "org.jasig.cas.services.DefaultRegisteredServiceProperty",
      "values" : [ "java.util.HashSet", [ "duo-two-factor" ] ]
    },
    "mfa_attribute_name" : {
      "@class" : "org.jasig.cas.services.DefaultRegisteredServiceProperty",
      "values" : [ "java.util.HashSet", [ "isMemberOf" ] ]
    },
    "mfa_attribute_pattern" : {
      "@class" : "org.jasig.cas.services.DefaultRegisteredServiceProperty",
      "values" : [ "java.util.HashSet", [ "faculty|staff" ] ]
    }
  }
}

```

### Opt-In
Opt-in mode requested by applications on demand when MFA is required:

```
https://<cas-server-url>/cas/login?service=xyz&authn_method=duo-two-factor
```
