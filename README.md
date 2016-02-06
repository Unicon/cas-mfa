## What is this project?  [![Maven Central](https://maven-badges.herokuapp.com/maven-central/net.unicon/cas-mfa/badge.svg?style=flat)](https://maven-badges.herokuapp.com/maven-central/net.unicon/cas-mfa)

[![Gitter](https://badges.gitter.im/Join Chat.svg)](https://gitter.im/Unicon/cas-mfa?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)


> This project is made public here on Github as part of Unicon's [Open Source Support program](https://unicon.net/opensource).
Professional Support / Integration Assistance for this module is available. For more information [visit](https://unicon.net/opensource/cas).

This is a project to develop free and open source compatibly licensed extensions for the CAS server `v4.1.x` product implementing

* support for authenticating using multiple authentication factors
* support for relying parties (CAS-using applications) understanding how strongly the user authenticated from the 
ticket validation response, and
* support for relying parties exerting authentication strength requirements.

## Requirements
* JDK 7+
* Apache Maven 3.3.x

## MultiFactor Support
* `duo-two-factor` (via DuoSecurity)

## Build Status
* [![Build Status](https://secure.travis-ci.org/Unicon/cas-mfa.png)](http://travis-ci.org/Unicon/cas-mfa)
* [ ![Codeship Status for Unicon/cas-mfa](https://www.codeship.io/projects/0bbd72d0-b74c-0130-d193-1eff452fc99e/status?branch=master)](https://www.codeship.io/projects/4315)


## Configuration

### AuthN Methods
An `authn-methods.conf` file is expected to be found at `/etc/cas` with the following content:

```json
[ {
  "rank" : 1,
  "name" : "duo-two-factor"
} ]

```
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