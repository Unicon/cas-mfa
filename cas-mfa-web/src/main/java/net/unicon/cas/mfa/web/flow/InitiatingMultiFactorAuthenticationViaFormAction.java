package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.addons.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestResolver;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.web.flow.AuthenticationViaFormAction;
import org.jasig.cas.web.support.WebUtils;
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
 *
 * @author Misagh Moayyed
 */
public class InitiatingMultiFactorAuthenticationViaFormAction extends AbstractMultiFactorAuthenticationViaFormAction {

    /**
     * The wrapper authentication action.
     */
    private final AuthenticationViaFormAction wrapperAuthenticationAction;

    /**
     * MultiFactorAuthenticationRequestResolver.
     */
    private final MultiFactorAuthenticationRequestResolver multiFactorAuthenticationRequestResolver;

    /**
     * The authentication support.
     */
    private final AuthenticationSupport authenticationSupport;

    /**
     * Instantiates a new initiating multi factor authentication via form action.
     *
     * @param authenticationViaFormAction the authentication via form action
     * @param multiFactorAuthenticationRequestResolver the mfa request resolver
     * @param authenticationSupport the authenticationSupport
     */
    public InitiatingMultiFactorAuthenticationViaFormAction(final AuthenticationViaFormAction authenticationViaFormAction,
                                                final MultiFactorAuthenticationRequestResolver multiFactorAuthenticationRequestResolver,
                                                final AuthenticationSupport authenticationSupport) {

        this.wrapperAuthenticationAction = authenticationViaFormAction;
        this.multiFactorAuthenticationRequestResolver = multiFactorAuthenticationRequestResolver;
        this.authenticationSupport = authenticationSupport;
    }

    /* (non-Javadoc)
     * @see net.unicon.cas.mfa.web.flow.AbstractMultiFactorAuthenticationViaFormAction#doAuthentication
     * (org.springframework.webflow.execution.RequestContext, org.jasig.cas.authentication.principal.Credentials
     *  org.springframework.binding.message.MessageContext, String)
     */
    @Override
    protected final Event doAuthentication(final RequestContext context, final Credentials credentials,
            final MessageContext messageContext, final String id)
            throws Exception {

        final String primaryAuthnEventId = this.wrapperAuthenticationAction.submit(context, credentials, messageContext);
        final Event primaryAuthnEvent = new Event(this, primaryAuthnEventId);
        if (!success().getId().equals(primaryAuthnEvent.getId())) {
            return primaryAuthnEvent;
        }

        final MultiFactorAuthenticationRequestContext mfaRequest =
                this.multiFactorAuthenticationRequestResolver.resolve(
                        this.authenticationSupport.getAuthenticationFrom(WebUtils.getTicketGrantingTicketId(context)),
                        WebApplicationService.class.cast(WebUtils.getService(context)));


        if (mfaRequest != null) {
            /*
             * Put this mfa request into the conversation scope
               to be accessed and transformed into instances of
               appropriate MultiFactorAuthenticationSupportingWebApplicationService by mfa subflows
            */
            putIntoConversationScope(mfaRequest, context);
            return doMultiFactorAuthentication(context, credentials, messageContext, id);
        }
        return primaryAuthnEvent;
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
                                                              final Credentials credentials,
                                                              final MessageContext messageContext, final String id) {
        if (WebUtils.getService(context) instanceof MultiFactorAuthenticationSupportingWebApplicationService) {
            return super.getSuccessEvent(context);
        }
        return new Event(this, MFA_SUCCESS_EVENT_ID_PREFIX + authentication.getPrincipal().getAttributes().get(CONST_PARAM_AUTHN_METHOD));
    }

    /**
     * Put mfa request into SWF's conversation scope.
     *
     * @param mfaRequest mfaRequest
     * @param requestContext SWF requestContext
     */
    private void putIntoConversationScope(final MultiFactorAuthenticationRequestContext mfaRequest, final RequestContext requestContext) {
        requestContext.getConversationScope().put("mfaRequest", mfaRequest);
    }
}
