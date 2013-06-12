package net.unicon.cas.mfa.web.flow;

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

    private final AuthenticationViaFormAction wrapperAuthenticationAction;

    public InitiatingMultiFactorAuthenticationViaFormAction(final AuthenticationViaFormAction authenticationViaFormAction) {
        this.wrapperAuthenticationAction = authenticationViaFormAction;
    }

    @Override
    protected Event doAuthentication(final RequestContext context, final Credentials credentials, final MessageContext messageContext)
            throws Exception {
        return new Event(this, this.wrapperAuthenticationAction.submit(context, credentials, messageContext));
    }

    public final void setWarnCookieGenerator(final CookieGenerator warnCookieGenerator) {
        this.wrapperAuthenticationAction.setWarnCookieGenerator(warnCookieGenerator);
    }

}
