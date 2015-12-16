## What is this project?  [![Maven Central](https://maven-badges.herokuapp.com/maven-central/net.unicon/cas-mfa/badge.svg?style=flat)](https://maven-badges.herokuapp.com/maven-central/net.unicon/cas-mfa)

[![Gitter](https://badges.gitter.im/Join Chat.svg)](https://gitter.im/Unicon/cas-mfa?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)


> This project is made public here on Github as part of Unicon's [Open Source Support program](https://unicon.net/opensource).
Professional Support / Integration Assistance for this module is available. For more information [visit](https://unicon.net/opensource/cas).

This is a project to develop free and open source compatibly licensed extensions for the CAS server `v4.1.x` product implementing

* support for authenticating using multiple authentication factors
* support for relying parties (CAS-using applications) understanding how strongly the user authenticated from the ticket validation response, and
* support for relying parties exerting authentication strength requirements.

The intention is to develop a solution that can be adopted by current CAS adopters.

## Requirements
* JDK 7~8
* Maven 3
* Tomcat 7~8

## MultiFactor Support
* `duo-two-factor` (via DuoSecurity)

## Documentation
Please review [the project wiki](https://github.com/Unicon/cas-mfa/wiki) for additional information on scope, functionality and how-to walkthroughs.

## Build Status
* [![Build Status](https://secure.travis-ci.org/Unicon/cas-mfa.png)](http://travis-ci.org/Unicon/cas-mfa)
* [ ![Codeship Status for Unicon/cas-mfa](https://www.codeship.io/projects/0bbd72d0-b74c-0130-d193-1eff452fc99e/status?branch=master)](https://www.codeship.io/projects/4315)


