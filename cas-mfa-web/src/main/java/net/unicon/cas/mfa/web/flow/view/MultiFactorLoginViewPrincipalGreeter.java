package net.unicon.cas.mfa.web.flow.view;

import org.jasig.cas.authentication.principal.Principal;

/**
 * Defines an abstraction by which principals can be greeted in the view.
 * @author Misagh Moayyed
 */
public interface MultiFactorLoginViewPrincipalGreeter {
    /**
     * Return the identifier that is to used to greet the credentials
     * in the view.
     * @param p the principal we are trying to welcome to the view.
     * @return the greetee
     */
    String getPersonToGreet(final Principal p);
}
