#!/bin/bash

echo -e "Evaluating change before pushing to Sonatype..."

# Only invoke the deployment to Sonatype when it's not a PR and only for master
if [ "$TRAVIS_PULL_REQUEST" == "false" ] && [ "$TRAVIS_BRANCH" == "master" ]; then
  echo -e "Starting to deploy to Sonatype..."
  mvn deploy --settings ./travis/settings.xml
  echo -e "Successfully deployed SNAPSHOT artifacts to Sonatype under Travis job ${TRAVIS_JOB_NUMBER}"
else
  echo -e "Skipped Sonatype deployment. This is either a pull request or a change on a different branch other than master"
fi 
echo -e "Fnished deploying to Sonatype."
