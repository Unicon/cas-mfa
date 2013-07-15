# Readme for cas-mfa-java sub-module

## What is this

This module is for the Java source code of the multifactor authentication extensions for CAS.
It builds to a .jar.

This module is intended to include all the Java you need to add to a CAS implementation to take advantage of the extended multifactor authentication features in this project.

Of course, it's kind of useless all by itself, since you also need Web application components, which live in the parallel `cas-mfa-web` directory.  Those Web components depend on these Java components.

This is kind of complicated and may not be the final answer here.

## How do I build it?

In this directory, run

    mvn package

This will yield a `target` directory containing, among other artifacts, a `cas-mfa-java-{VERSION}.jar`, where {VERSION} is, as of this writing, "0.0.1-SNAPSHOT".  As in, `cas-mfa-java-0.0.1-SNAPSHOT.jar`.

You'd then include that .jar in an application, e.g. by declaring it as a Maven dependency in a `pom.xml`.

The `cas-mfa-web` project does this, and the top level (up one directory) `pom.xml` automates first building this .jar and then making use of it in the other (i.e., .war) artifacts it builds.

