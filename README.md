# What is this project

This is a project to develop free and open source compatibly licensed extensions for the current-generation CAS server product implementing
* support for authenticating using multiple authentication factors
* support for relying parties (CAS-using applications) understanding how strongly the user authenticated from the ticket validation response, and
* support for relying parties exerting authentication strength requirements.

Unicon is undertaking this project under contract for Evergreen State College as an outcome of a successful response to a lovely RFP requisitioning this software development and thoughtfully insisting that the work product be free and open source software.

The intention is to develop a solution that can be adopted by current CAS adopters.

# What are these directories

This project is currently structured as three sub-projects

## cas-mfa-java

Java classes and interfaces that build to a .jar

## cas-mfa-web

Web components (JSPs, Spring Web Flow configuration, etc.) that build to a .war.

These Web components can depend on the cas-mfa-java .jar

## webapp-overlay-example

An example of how a CAS adopter would compose a local good-practices maven overlay configuration to build a localized CAS server incorporating the features in this project.


# How do I build this and try it out?

*Good question!*  Currently, you don't, because there's nothing hear yet.  Come back soon.


# Where will this code live eventually?

*Good question!*  

In part, we'll figure that out when we get there.

One potential next step for this code is to merge into Unicon's `cas-addons` (for Java components) and `unicon-cas-overlay` (for non-Java components needing inclusion in a webapp).  This has some advantages is that Maven repository publication for `cas-addons` is already in place, `cas-addons` already has decently wide visibility and adoption such that it would raise visibility of the options created by this work, and the sort of CAS adopter interested in adopting this extension is probably also interested in considering the features in `cas-addons` such that we can save people some trouble by making these one bundle of self-consistent extensions.

# Will this code merge into the Apereo CAS server product itself?

That's a possibility.  Certainly we want to tee up the licensing alignment, the code quality, etc., so that that's a potential path forward.

Like the approach with `cas-addons`, the idea is to first make it feasible to try out and adopt these extensions as an add-on in addition to an Apereo CAS server implementation.  This is reminiscent of the `ClearPass` CAS extension before it hit the big time in gaining distribution with the Apereo (then, Jasig) CAS server product itself.

We're open to and encouraging of this project succeeding in terms of the code being adopted into CAS server, but we'll consider successful adoption as a CAS extension equally successful.

The point is to add value to eventually numerous CAS implementations through adoption of this functionality, regardless of how the extension is factored.


# How do I engage with and contribute to this?

*Good question!*  We're still bootstrapping this project.  

Eventually, we should be able to accept Pull Requests, communicate via the Issue Tracker, document design via the Wiki, etc.

We intend to discuss this development effort publicly on the `cas-dev` email list.

Jim Vales is Unicon's project manager for this project.  You can contact him via [Unicon's contact form](http://www.unicon.net/contact).


