package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.addons.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;
import org.apache.commons.lang.StringUtils;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.core.collection.AttributeMap;
import org.springframework.webflow.core.collection.LocalAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.FlowSession;
import org.springframework.webflow.execution.RequestContext;

import javax.validation.constraints.NotNull;

/**
 * An action to obtain/construct the {@link MultiFactorCredentials} instance and pass it along
 * to the subsequent authentication flow. For transitions between authentication sequences and flows,
 * credentials need to be reconstructed before moving on to the next flow.
 * @author Misagh Moayyed
 */
public final class GenerateMultiFactorCredentialsAction extends AbstractAction {

    private static final Logger LOGGER = LoggerFactory.getLogger(GenerateMultiFactorCredentialsAction.class);

    private static final String EVENT_ID_SUCCESS = "success";

    /**
     * The constant ATTRIBUTE_ID_MFA_CREDENTIALS
     * that indicates the {@link MultiFactorCredentials} instance created
     * and put into the scope;
     */
    protected static final String ATTRIBUTE_ID_MFA_CREDENTIALS= "mfaCredentials";

    /** The authentication support. */
    private AuthenticationSupport authenticationSupport;


    /**
     * Sets the authentication support.
     *
     * @param authSupport the new authentication support
     */
    public void setAuthenticationSupport(final AuthenticationSupport authSupport) {
        this.authenticationSupport = authSupport;
    }

    /**
     * Construct the {@link MultiFactorCredentials} instance by chaining current {@link Credentials}
     * and the {@link Authentication}.
     * @param context the request context
     * @param upCredentials the credentials to authenticate
     * @param id the identifier for the credentials used.
     * @return an instance of {@link MultiFactorCredentials}
     * @throws NoAuthenticationContextAvailable if the authentication cannot be established from the flow context
     * from what has already been authenticated as the principal
     */
    private Credentials createCredentials(final RequestContext context, @NotNull final Credentials upCredentials,
            @NotNull final String id) throws NoAuthenticationContextAvailable {
        final Authentication authentication = getCasAuthentication(context);
        if (authentication == null) {
            LOGGER.debug("No authentication context is available.");
            throw new NoAuthenticationContextAvailable();
        }

        LOGGER.debug("Retrieved authentication context. Building multifactor credentials...");
        final MultiFactorCredentials credentials = getMfaCredentialsInstanceFromContext(context);

        LOGGER.debug("Added authentication to the chain");
        credentials.addAuthenticationToChain(authentication);

        if (id != null && upCredentials != null) {
            LOGGER.debug("Added credentials to the chain by id [{}]", id);
            credentials.getChainedCredentials().put(id, upCredentials);
        }
        MultiFactorRequestContextUtils.setMfaCredentials(context, credentials);

        LOGGER.debug("Added multifactor credentials to the request context.");
        return credentials;
    }

    /**
     * Obtain the {@link Authentication} object from the webflow's flow scope. If none,
     * attempt to obtain the authentication object from the current TGT.
     * @param context the request context
     * @return the {@link Authentication} object
     */
    private Authentication getCasAuthentication(final RequestContext context) {

        final Authentication authentication = MultiFactorRequestContextUtils.getAuthentication(context);

        if (authentication == null) {
            LOGGER.debug("Request is missing authentication context. Examining TGT...");
            final String tgt = MultiFactorRequestContextUtils.getTicketGrantingTicketId(context);
            if (!StringUtils.isBlank(tgt)) {
                LOGGER.debug("Retrieving authentication context from TGT [{}]", tgt);
                return this.authenticationSupport.getAuthenticationFrom(tgt);
            }
        }

        return authentication;
    }

    /**
     * Gets the mfa credentials instance from context.
     *
     * @param context the context
     * @return the mfa credentials instance from context
     */
    private MultiFactorCredentials getMfaCredentialsInstanceFromContext(final RequestContext context) {
        LOGGER.debug("Attempting to collect multifactor credentials from the context...");
        final MultiFactorCredentials c = MultiFactorRequestContextUtils.getMfaCredentials(context);
        if (c == null) {
            LOGGER.debug("Context is missing multifactor credentials. Initializing a new instance...");
            return new MultiFactorCredentials();
        }
        return c;

    }

    @Override
    protected Event doExecute(final RequestContext context) {
        final FlowSession session = context.getFlowExecutionContext().getActiveSession();
        LOGGER.debug("Authentication has entered the flow [{}] executing state [{}",
                context.getActiveFlow().getId(), session.getState().getId());
        final UsernamePasswordCredentials creds = (UsernamePasswordCredentials)
                session.getScope().getRequired("credentials", UsernamePasswordCredentials.class);
        final String id = creds != null ? creds.getUsername() : null;

        final Credentials mfaCreds = createCredentials(context, creds, id);
        final AttributeMap map = new LocalAttributeMap(ATTRIBUTE_ID_MFA_CREDENTIALS, mfaCreds);
        return new Event(this, EVENT_ID_SUCCESS, map);
    }
}
