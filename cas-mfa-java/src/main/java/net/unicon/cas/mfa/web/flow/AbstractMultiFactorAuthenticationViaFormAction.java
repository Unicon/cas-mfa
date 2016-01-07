package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.mfa.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestResolver;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationTransactionContext;
import net.unicon.cas.mfa.authentication.RequestedAuthenticationMethodRankingStrategy;
import net.unicon.cas.mfa.web.flow.event.ErroringMultiFactorAuthenticationSpringWebflowEventBuilder;
import net.unicon.cas.mfa.web.flow.event.MultiFactorAuthenticationSpringWebflowEventBuilder;
import net.unicon.cas.mfa.web.flow.event.ServiceAuthenticationMethodMultiFactorAuthenticationSpringWebflowEventBuilder;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;
import net.unicon.cas.mfa.web.support.AuthenticationMethodVerifier;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationManager;
import org.jasig.cas.authentication.Credential;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.principal.Response.ResponseType;
import org.jasig.cas.authentication.principal.SimpleWebApplicationServiceImpl;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.web.support.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageContext;
import org.springframework.util.Assert;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.definition.FlowDefinition;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import java.util.List;

/**
 * An abstraction that specifies how the authentication flow should behave.
 * It primarily acts as a wrapper recipient of authentication requests via form.
 *
 * <p>Implementations are notified of the authentication type (MFA, non-MFA)
 * and are responsible to act accordingly.
 *
 * @author Misagh Moayyed
 */
@SuppressWarnings("deprecation")
public abstract class AbstractMultiFactorAuthenticationViaFormAction extends AbstractAction {

    /**
     * The logger.
     */
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * The authentication manager.
     */
    @NotNull
    protected AuthenticationManager authenticationManager;

    /**
     * The central authentication service.
     */
    @NotNull
    protected CentralAuthenticationService cas;

    /**
     * MultiFactorAuthenticationRequestResolver.
     */
    protected final MultiFactorAuthenticationRequestResolver multiFactorAuthenticationRequestResolver;

    /**
     * The authentication support.
     */
    protected final AuthenticationSupport authenticationSupport;


    /**
     * The authenticationMethodVerifier.
     */
    protected final AuthenticationMethodVerifier authenticationMethodVerifier;


    /**
     * Authentication method ranking strategy.
     */
    private final RequestedAuthenticationMethodRankingStrategy authnMethodRankingStrategy;

    /**
     * The CAS server hostname.
     */
    private final String hostname;

    private MultiFactorAuthenticationSpringWebflowEventBuilder successfulEventBuilder =
            new ServiceAuthenticationMethodMultiFactorAuthenticationSpringWebflowEventBuilder();

    private MultiFactorAuthenticationSpringWebflowEventBuilder errorEventBuilder =
            new ErroringMultiFactorAuthenticationSpringWebflowEventBuilder();

    /**
     * Ctor.
     *
     * @param multiFactorAuthenticationRequestResolver multiFactorAuthenticationRequestResolver
     * @param authenticationSupport authenticationSupport
     * @param authenticationMethodVerifier authenticationMethodVerifier
     * @param authenticationMethodRankingStrategy authenticationMethodRankingStrategy
     * @param hostname the CAS server hostname
     */
    protected AbstractMultiFactorAuthenticationViaFormAction(
            final MultiFactorAuthenticationRequestResolver multiFactorAuthenticationRequestResolver,
            final AuthenticationSupport authenticationSupport,
            final AuthenticationMethodVerifier authenticationMethodVerifier,
            final RequestedAuthenticationMethodRankingStrategy authenticationMethodRankingStrategy,
            final String hostname) {

        this.multiFactorAuthenticationRequestResolver = multiFactorAuthenticationRequestResolver;
        this.authenticationSupport = authenticationSupport;
        this.authenticationMethodVerifier = authenticationMethodVerifier;
        this.authnMethodRankingStrategy = authenticationMethodRankingStrategy;
        this.hostname = hostname;
    }

    /**
     * Determine whether the request is MFA compliant.
     *
     * @param context the request context
     *
     * @return true, if this is a MFA request.
     */
    private static boolean isMultiFactorAuthenticationRequest(final RequestContext context) {
        return MultiFactorRequestContextUtils.getMfaTransaction(context) != null;
    }

    /**
     * In the event of an MFA request, authenticate the credentials by default, and place
     * the authentication context back into the flow.
     * <p>Coming from the 'doAuthentication' and checking if the principal mfa source has been ranked or not
     * Or if coming straight from initial transition. In either case, if there is no mfa service already in the flow scope
     * try to get the principal attribute sourced mfa request and re-rank the existing mfa tx, so the mfa service is
     * always available in the flow scope for downstream subflows.
     * <p>If we get to this method, the mfa transaction is guaranteed to be in the flow scope.
     *
     * @param context request context
     * @param credentials the requesting credentials
     * @param messageContext the message bundle manager
     * @param id the identifier of the credential, based on implementation provided in the flow setup.
     *
     * @return the resulting event
     *
     * @throws Exception the exception
     */
    protected final Event doMultiFactorAuthentication(final RequestContext context, final Credential credentials,
                                                      final MessageContext messageContext, final String id) throws Exception {

        Assert.notNull(id);
        Assert.notNull(credentials);

        try {
            final Authentication auth = this.authenticationManager.authenticate(credentials);
            if (MultiFactorRequestContextUtils.getMultifactorWebApplicationService(context) == null) {
                final List<MultiFactorAuthenticationRequestContext> mfaRequest =
                        getMfaRequestOrNull(auth, WebUtils.getService(context), context);
                //No principal attribute sourced mfa method request. Just get the highest ranked mfa service from existing ones
                if (mfaRequest == null) {
                    MultiFactorRequestContextUtils.setMultifactorWebApplicationService(context,
                            getHighestRankedMfaRequestFromMfaTransaction(context));
                } else {
                    final MultiFactorAuthenticationSupportingWebApplicationService highestService =
                            addToMfaTransactionAndGetHighestRankedMfaRequest(mfaRequest, context);
                    MultiFactorRequestContextUtils.setMultifactorWebApplicationService(context, highestService);
                    MultiFactorRequestContextUtils.setRequiredAuthenticationMethod(context, highestService.getAuthenticationMethod());
                }
            }

            final Event result = multiFactorAuthenticationSuccessful(auth, context, credentials, messageContext, id);
            MultiFactorRequestContextUtils.setAuthentication(context, auth);
            return result;
        } catch (final AuthenticationException e) {
            populateErrorsInstance(e.getCode(), messageContext);
            MultiFactorRequestContextUtils.setAuthenticationExceptionInFlowScope(context, e);
            logger.error(e.getMessage(), e);
        }
        return getErrorEvent(context);
    }


    /**
     * In the event of a non-MFA request, return the result of {@link #getErrorEvent(RequestContext)} by default.
     * Implementations are expected to override this method if they wish to respond to authentication
     * requests.
     *
     * @param context request context
     * @param credentials the requesting credentials
     * @param messageContext the message bundle manager
     * @param id the identifier of the credential, based on implementation provided in the flow setup
     *
     * @return the resulting event
     *
     * @throws Exception the exception
     */
    protected abstract Event doAuthentication(final RequestContext context, final Credential credentials,
                                              final MessageContext messageContext, final String id) throws Exception;

    /**
     * Checks if is valid login ticket.
     *
     * @param context the context
     * @param messageContext the message context
     *
     * @return true, if is valid login ticket
     */
    protected final boolean isValidLoginTicket(final RequestContext context, final MessageContext messageContext) {
        final String authoritativeLoginTicket = WebUtils.getLoginTicketFromFlowScope(context);
        final String providedLoginTicket = WebUtils.getLoginTicketFromRequest(context);
        if (!authoritativeLoginTicket.equals(providedLoginTicket)) {
            logger.warn("Invalid login ticket {}", providedLoginTicket);
            final String code = "INVALID_TICKET";
            messageContext.addMessage(new MessageBuilder().error().code(code).arg(providedLoginTicket).defaultText(code).build());
            return false;
        }
        return true;
    }

    /**
     * Submit.
     *
     * @param context the context
     * @param credentials the credentials
     * @param messageContext the message context
     * @param id the id
     *
     * @return the event
     *
     * @throws Exception the exception
     */
    private Event submit(final RequestContext context, final Credential credentials, final MessageContext messageContext,
                              final String id) throws Exception {

        if (isMultiFactorAuthenticationRequest(context)) {
            if (isValidLoginTicket(context, messageContext)) {
                return doMultiFactorAuthentication(context, credentials, messageContext, id);
            }
            return getErrorEvent(context);
        }
        return doAuthentication(context, credentials, messageContext, id);
    }

    /**
     * Multifactor authentication successful.
     *
     * @param authentication the authentication
     * @param context        the context
     * @param credentials    the credentials
     * @param messageContext the message context
     * @param id             the id
     * @return the event
     * @throws Exception the exception
     */
    protected abstract Event multiFactorAuthenticationSuccessful(final Authentication authentication, final RequestContext context,
                                                                 final Credential credentials, final MessageContext messageContext,
                                                                 final String id) throws Exception;

    /**
     * CAS instance used to handle authentications. This CAS instance is only
     * effective when the incoming service does not specify a valid loa.
     *
     * @param centralAuthenticationService the cas instance.
     */
    public final void setCentralAuthenticationService(final CentralAuthenticationService centralAuthenticationService) {
        this.cas = centralAuthenticationService;
    }


    public void setSuccessfulEventBuilder(final MultiFactorAuthenticationSpringWebflowEventBuilder successfulEventBuilder) {
        this.successfulEventBuilder = successfulEventBuilder;
    }

    public void setErrorEventBuilder(final MultiFactorAuthenticationSpringWebflowEventBuilder errorEventBuilder) {
        this.errorEventBuilder = errorEventBuilder;
    }

    /**
     * Authentication manager instance to authenticate the user by its configured
     * handlers as the first leg of an multifactor authentication sequence.
     *
     * @param manager the new multifactor authentication manager
     */
    public final void setMultiFactorAuthenticationManager(final AuthenticationManager manager) {
        this.authenticationManager = manager;
    }

    /**
     * The webflow error event id.
     *
     * @param context the context
     * @return error event id
     */
    protected final Event getErrorEvent(final RequestContext context) {
        final Event event = this.errorEventBuilder.buildEvent(context);
        final FlowDefinition flow = context.getActiveFlow();
        final String flowId = flow != null ? flow.getId() : "[none]";
        logger.debug("Returning an error event [{}] in the active flow id [{}]", event.getId(), flowId);
        return event;

    }

    /**
     * Return the mfa webflow id.
     *
     * @param context the request context
     *
     * @return the webflow id
     */
    protected final Event getSuccessEvent(final RequestContext context) {
        return this.successfulEventBuilder.buildEvent(context);
    }

    /* (non-Javadoc)
     * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
     */
    @Override
    public void afterPropertiesSet() throws Exception {
    }

    /**
     * Populate errors instance.
     *
     * @param code the error code
     * @param messageContext the message context
     */
    protected final void populateErrorsInstance(final String code, final MessageContext messageContext) {
        try {
            messageContext.addMessage(new MessageBuilder().error().code(code).defaultText(code).build());
        }  catch (final Exception fe) {
            logger.error(fe.getMessage(), fe);
        }
    }

    @Override
    protected final Event doExecute(final RequestContext ctx) throws Exception {
        final Credential credentials = WebUtils.getCredential(ctx);
        final MessageContext messageContext = ctx.getMessageContext();


        if (credentials != null) {
            final String id = credentials.getId();
            return submit(ctx, credentials, messageContext, id);
        }
        logger.warn("Credentials could not be determined, or no username was associated with the request.");
        return getErrorEvent(ctx);
    }

    /**
     * Get MFA request or null.
     *
     * <p>The service may be null and not available in the context, in cases where
     * one is simply logging into CAS without noting the service application.
     * In those cases, we need to mock up a service instance in order for authentication
     * request resolver (i.e. based on principal attributes) to be able to establish the
     * mfa context and walk the user through the mfa sequence if need be. This dummy service
     * is based on the hostname provided to CAS via configuration, and is CAS itself.</p>
     * @param authentication the authentication
     * @param service the service
     * @param context the context
     *
     * @return mfa request or null
     */
    protected List<MultiFactorAuthenticationRequestContext> getMfaRequestOrNull(final Authentication authentication,
                                                                          final WebApplicationService service,
                                                                          final RequestContext context) {

        WebApplicationService serviceToUse = service;
        final HttpServletRequest request = HttpServletRequest.class.cast(context.getExternalContext().getNativeRequest());
        final String responseMethod = request.getParameter("method");
        final ResponseType responseType = "POST".equalsIgnoreCase(responseMethod) ? ResponseType.POST : ResponseType.REDIRECT;
        if (service == null) {
            serviceToUse = new SimpleWebApplicationServiceImpl(this.hostname);
        }

        final List<MultiFactorAuthenticationRequestContext> mfaRequests =
                this.multiFactorAuthenticationRequestResolver.resolve(authentication, serviceToUse, responseType);
        if (mfaRequests != null) {
            for (final MultiFactorAuthenticationRequestContext mfaRequest : mfaRequests) {
                this.authenticationMethodVerifier.verifyAuthenticationMethod(mfaRequest.getMfaService().getAuthenticationMethod(),
                        mfaRequest.getMfaService(),
                        request);

                logger.info("There is an existing mfa request for service [{}] with a requested authentication method of [{}]",
                        mfaRequest.getMfaService().getId(), mfaRequest.getMfaService().getAuthenticationMethod());
            }
            logger.debug("Resolved {} multifactor authentication requests", mfaRequests.size());
            if (mfaRequests.isEmpty()) {
                logger.debug("No multifactor authentication requests could be resolved.");
                return null;
            }
        }
        return mfaRequests;
    }


    /**
     * Add the request to mfa transaction, re-rank and return the newly ranked one.
     *
     * @param mfaRequests the mfaRequest
     * @param context the context
     *
     * @return newly ranked mfa request in the current mfa transaction
     */
    protected MultiFactorAuthenticationSupportingWebApplicationService
                addToMfaTransactionAndGetHighestRankedMfaRequest(final List<MultiFactorAuthenticationRequestContext> mfaRequests,
                                                     final RequestContext context) {

        MultiFactorAuthenticationTransactionContext mfaTx = MultiFactorRequestContextUtils.getMfaTransaction(context);
        if (mfaTx == null && !mfaRequests.isEmpty()) {
            final WebApplicationService svc = mfaRequests.get(0).getMfaService();
            mfaTx = new MultiFactorAuthenticationTransactionContext(svc.getId());
        }
        for (final MultiFactorAuthenticationRequestContext mfaRequest : mfaRequests) {
            mfaTx.addMfaRequest(mfaRequest);
        }

        MultiFactorRequestContextUtils.setMfaTransaction(context, mfaTx);
        return getHighestRankedMfaRequestFromMfaTransaction(context);
    }

    /**
     * Get highest ranked mfa request from mfa transaction. Assumes that mfa transaction is already in the flow scope.
     *
     * @param context the context
     *
     * @return highest ranked mfa request
     */
    private MultiFactorAuthenticationSupportingWebApplicationService
            getHighestRankedMfaRequestFromMfaTransaction(final RequestContext context) {
        return this.authnMethodRankingStrategy.computeHighestRankingAuthenticationMethod(
                MultiFactorRequestContextUtils.getMfaTransaction(context));
    }
}
