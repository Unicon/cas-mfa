# What is this project?

This is a project to develop free and open source compatibly licensed extensions for the current-generation CAS server product implementing
* support for authenticating using multiple authentication factors
* support for relying parties (CAS-using applications) understanding how strongly the user authenticated from the ticket validation response, and
* support for relying parties exerting authentication strength requirements.

Unicon is undertaking this project under contract for Evergreen State College as an outcome of a successful response to a lovely RFP requisitioning this software development and thoughtfully insisting that the work product be free and open source software.

The intention is to develop a solution that can be adopted by current CAS adopters.

#Documentation
Please review [the project wiki](https://github.com/Unicon/cas-mfa/wiki) for additional information on scope, functionality and how-to walkthroughs. 

# Build Status

* [![Build Status](https://secure.travis-ci.org/Unicon/cas-mfa.png)](http://travis-ci.org/Unicon/cas-mfa)
* [ ![Codeship Status for Unicon/cas-mfa](https://www.codeship.io/projects/0bbd72d0-b74c-0130-d193-1eff452fc99e/status?branch=master)](https://www.codeship.io/projects/4315)

# Live Demo
Snapshots are automatically deployed to [heroku.com](http://heroku.com). This is accomodated by the [codeship](http://codeship.io) plugin
configured for the repository to auto build the `heroku` branch.

You may experiment with the live demo at the following url:
[https://casmfa.herokuapp.com](https://casmfa.herokuapp.com) (Note: If you receive an "Application Error" upon initial access,
try refreshing the page once)
ding in terms of the code being adopted into CAS server, but we'll consider successful adoption as a CAS extension equally successful.

The point is to add value to eventually numerous CAS implementations through adoption of this functionality, regardless of how the extension is factored.


