package net.unicon.cas.mfa.web.flow.view;

import org.jasig.cas.authentication.principal.Principal;
import org.springframework.binding.message.MessageContext;

/**
 * Defines an abstraction by which principals can be greeted in the view.
 * @author Misagh Moayyed
 */
public interface MultiFactorLoginViewPrincipalGreeter {
    /**
     * Return the identifier that is to used to greet the credentials
     * in the view.
     * @param p the principal we are trying to welcome to the view.
     * @param messageContext context to resolve the message code associated with the greeting
     * @return the greetee
     */
    String getPersonToGreet(final Principal p, MessageContext messageContext);
}
