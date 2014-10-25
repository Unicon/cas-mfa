package com.toopher.integrations.cas.authentication;

import org.apache.log4j.Logger;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationMetaDataPopulator;
import org.jasig.cas.authentication.MutableAuthentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;

public class UsernamePasswordAuthenticationMetaDataPopulator implements AuthenticationMetaDataPopulator {
    private static Logger logger = Logger.getLogger("com.toopher.integrations.cas");


    @Override
    public Authentication populateAttributes(Authentication authentication, Credentials credentials) {
        if (credentials instanceof UsernamePasswordCredentials) {
            Principal simplePrincipal = new SimplePrincipal(authentication.getPrincipal().getId());
            Long existingLoaValue = 0L;
            if (authentication.getAttributes().containsKey(LevelOfAssurance.LOA_ATTRIBUTE_NAME)) {
                existingLoaValue = Long.valueOf(authentication.getAttributes().get(LevelOfAssurance.LOA_ATTRIBUTE_NAME).toString());
            } else {
                existingLoaValue = 0L;
            }

            MutableAuthentication mutableAuthentication = new MutableAuthentication(simplePrincipal, authentication.getAuthenticatedDate());
            mutableAuthentication.getAttributes().putAll(authentication.getAttributes());

            LevelOfAssurance newLoa = new LevelOfAssurance(existingLoaValue);
            newLoa.setUsernamePasswordRequired(true);
            logger.debug("authentication gains LOA_USERNAME_PASSWORD");

            logger.debug("final LOA value = " + newLoa.asString());

            mutableAuthentication.getAttributes().put(LevelOfAssurance.LOA_ATTRIBUTE_NAME, newLoa.asLong());
            return mutableAuthentication;

        } else {
            return authentication;
        }

    }

}
