## What is this project?

This is a project to develop free and open source compatibly licensed extensions for the CAS server `v3.5.2.1` product implementing
* support for authenticating using multiple authentication factors
* support for relying parties (CAS-using applications) understanding how strongly the user authenticated from the ticket validation response, and
* support for relying parties exerting authentication strength requirements.

The intention is to develop a solution that can be adopted by current CAS adopters.

## Requirements
* JDK 6
* Maven 3
* Tomcat 7

## MultiFactor Support
* `duo-two-factor` (via DuoSecurity)
* `yubikey-two-factor` (via YubiKey)
* `radius-two-factor` (via RADIUS OTP)
* `strong-two-factor` (Custom)

## Documentation
Please review [the project wiki](https://github.com/Unicon/cas-mfa/wiki) for additional information on scope, functionality and how-to walkthroughs.

## Build Status
* [![Build Status](https://secure.travis-ci.org/Unicon/cas-mfa.png)](http://travis-ci.org/Unicon/cas-mfa)
* [ ![Codeship Status for Unicon/cas-mfa](https://www.codeship.io/projects/0bbd72d0-b74c-0130-d193-1eff452fc99e/status?branch=master)](https://www.codeship.io/projects/4315)


