package net.unicon.cas.mfa.web.flow;

import javax.validation.constraints.NotNull;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.RequestContext;

import net.unicon.cas.addons.authentication.AuthenticationSupport;
import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;

/**
 * An action to obtain/construct the {@link MultiFactorCredentials} instance and pass it along
 * to the subsequent authentication flow. For transitions between authentication sequences and flows,
 * credentials need to be reconstructed before moving on to the next flow.
 * @author Misagh Moayyed
 */
public final class GenerateMultiFactorCredentialsAction {

    private static final Logger LOGGER = LoggerFactory.getLogger(GenerateMultiFactorCredentialsAction.class);

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
     * @return an instance of {@link MultiFactorCredentials} or null if no authentication context available
     */
    public Credentials createCredentials(final RequestContext context, @NotNull final Credentials upCredentials, @NotNull final String id) {
        final Authentication authentication = getCasAuthentication(context);
        if (authentication == null) {
            LOGGER.debug("No authentication context is available.");
            return null;
        }

        LOGGER.debug("Retrieved authentication context. Building multifactor credentials...");
        final MultiFactorCredentials credentials = getMfaCredentialsInstanceFromContext(context);

        LOGGER.debug("Added authentication to the chain");
        credentials.getChainedAuthentications().add(authentication);

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
}
