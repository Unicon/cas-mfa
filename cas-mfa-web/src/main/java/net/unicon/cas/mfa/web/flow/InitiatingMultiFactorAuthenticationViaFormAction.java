/*
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package net.unicon.cas.mfa.web.flow;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD;

import javax.servlet.http.HttpServletRequest;

import net.unicon.cas.addons.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestResolver;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;
import net.unicon.cas.mfa.web.support.AuthenticationMethodVerifier;
import net.unicon.cas.mfa.web.support.MfaWebApplicationServiceFactory;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

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

    private final MfaWebApplicationServiceFactory mfaWebApplicationServiceFactory;

    private final AuthenticationMethodVerifier authenticationMethodVerifier;

    /**
     * Instantiates a new initiating multi factor authentication via form action.
     *
     * @param authenticationViaFormAction the authentication via form action
     * @param multiFactorAuthenticationRequestResolver the mfa request resolver
     * @param authenticationSupport the authenticationSupport
     * @param mfaWebApplicationServiceFactory the mfa web application service factory
     * @param authenticationMethodVerifier the authentication method verifier
     */
    public InitiatingMultiFactorAuthenticationViaFormAction(final AuthenticationViaFormAction authenticationViaFormAction,
                                                final MultiFactorAuthenticationRequestResolver multiFactorAuthenticationRequestResolver,
                                                final AuthenticationSupport authenticationSupport,
                                                final MfaWebApplicationServiceFactory mfaWebApplicationServiceFactory,
                                                final AuthenticationMethodVerifier authenticationMethodVerifier) {

        this.mfaWebApplicationServiceFactory = mfaWebApplicationServiceFactory;
        this.authenticationMethodVerifier = authenticationMethodVerifier;
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
            
            this.authenticationMethodVerifier.verifyAuthenticationMethod(mfaRequest.getAuthenticationMethod(),
                    mfaRequest.getTargetService(),
                    HttpServletRequest.class.cast(context.getExternalContext().getNativeRequest()));

            logger.info("There is an existing mfa request for service [{}] with a requested authentication method of [{}]",
                    mfaRequest.getTargetService().getId(), mfaRequest.getAuthenticationMethodSource());

            final MultiFactorAuthenticationSupportingWebApplicationService svc =
                    this.mfaWebApplicationServiceFactory.create(mfaRequest.getTargetService().getId(), 
                            mfaRequest.getTargetService().getId(),
                            mfaRequest.getTargetService().getArtifactId(),
                            mfaRequest.getAuthenticationMethod(),
                            mfaRequest.getAuthenticationMethodSource());
                    
            MultiFactorRequestContextUtils.setMultifactorWebApplicationService(context, svc);
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
}
