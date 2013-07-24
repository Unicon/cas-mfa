package net.unicon.cas.mfa.web.flow;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.web.flow.AuthenticationViaFormAction;
import org.springframework.binding.message.MessageContext;
import org.springframework.web.util.CookieGenerator;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * The multifactor authentication service action that branches to an loa-defined
 * subflow state based on the service loa requirement. If the requesting service
 * is an instance of {@link net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService},
 * this action would simply attempt to verify the given credentials based on
 * {@link #setMultiFactorAuthenticationManager(org.jasig.cas.authentication.AuthenticationManager)}
 * and will alter the webflow to the next leg of the authentication sequence.
 * @author Misagh Moayyed
 */
public class InitiatingMultiFactorAuthenticationViaFormAction extends AbstractMultiFactorAuthenticationViaFormAction {

    /** The wrapper authentication action. */
    private final AuthenticationViaFormAction wrapperAuthenticationAction;

    /**
     * Instantiates a new initiating multi factor authentication via form action.
     *
     * @param authenticationViaFormAction the authentication via form action
     */
    public InitiatingMultiFactorAuthenticationViaFormAction(final AuthenticationViaFormAction authenticationViaFormAction) {
        this.wrapperAuthenticationAction = authenticationViaFormAction;
    }

    /* (non-Javadoc)
     * @see net.unicon.cas.mfa.web.flow.AbstractMultiFactorAuthenticationViaFormAction#doAuthentication
     * (org.springframework.webflow.execution.RequestContext, org.jasig.cas.authentication.principal.Credentials
     *  org.springframework.binding.message.MessageContext)
     */
    @Override
    protected final Event doAuthentication(final RequestContext context, final Credentials credentials, final MessageContext messageContext)
            throws Exception {
        return new Event(this, this.wrapperAuthenticationAction.submit(context, credentials, messageContext));
    }

    /**
     * Sets the warn cookie generator.
     *
     * @param warnCookieGenerator the new warn cookie generator
     */
    public final void setWarnCookieGenerator(final CookieGenerator warnCookieGenerator) {
        this.wrapperAuthenticationAction.setWarnCookieGenerator(warnCookieGenerator);
    }

    @Override
    protected final Event multiFactorAuthenticationSuccessful(final Authentication authentication, final RequestContext context,
            final Credentials credentials, final MessageContext messageContext, final String id) {
        return super.getSuccessEvent(context);
    }

}
