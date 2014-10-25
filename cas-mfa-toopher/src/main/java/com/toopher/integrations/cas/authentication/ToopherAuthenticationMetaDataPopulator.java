package com.toopher.integrations.cas.authentication;

import org.apache.log4j.Logger;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationMetaDataPopulator;
import org.jasig.cas.authentication.MutableAuthentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import com.toopher.integrations.cas.authentication.principal.ToopherCredentials;

public class ToopherAuthenticationMetaDataPopulator implements AuthenticationMetaDataPopulator {
    private static Logger logger = Logger.getLogger("com.toopher.integrations.cas");


    @Override
    public Authentication populateAttributes(Authentication authentication, Credentials credentials) {
        if (credentials instanceof ToopherCredentials) {
            Principal simplePrincipal = new SimplePrincipal(authentication.getPrincipal().getId());
            MutableAuthentication mutableAuthentication = new MutableAuthentication(simplePrincipal, authentication.getAuthenticatedDate());
            // initialize the new authentication with the existing attributes
            mutableAuthentication.getAttributes().putAll(authentication.getAttributes());

            Long existingLoaValue = 0L;
            if (authentication.getAttributes().containsKey(LevelOfAssurance.LOA_ATTRIBUTE_NAME)) {
                existingLoaValue = Long.valueOf(authentication.getAttributes().get(LevelOfAssurance.LOA_ATTRIBUTE_NAME).toString());
            } else {
                existingLoaValue = LevelOfAssurance.LOA_USERNAME_PASSWORD_VAL;
            }

            ToopherCredentials toopherCredentials = (ToopherCredentials)credentials;
            LevelOfAssurance newLoa = new LevelOfAssurance(existingLoaValue);

            // a successful toopher authentication means at least LOA_TOOPHER is true
            newLoa.setToopherRequired(true);
            logger.debug("authentication gains LOA_TOOPHER");

            if (!toopherCredentials.getAutomated()) {
                logger.debug("authentication gains LOA_TOOPHER_DISALLOW_AUTOMATION");
                newLoa.setDisallowAutomationRequired(true);
            }
            if (toopherCredentials.getChallengeRequired()) {
                logger.debug("authentication gains LOA_TOOPHER_REQUIRE_CHALLENGE");
                newLoa.setChallengeRequired(true);
            }

            logger.debug("final LOA value = " + newLoa.asString());

            mutableAuthentication.getAttributes().put(LevelOfAssurance.LOA_ATTRIBUTE_NAME, newLoa.asLong());
            return mutableAuthentication;

        } else {
            return authentication;
        }

    }

}
