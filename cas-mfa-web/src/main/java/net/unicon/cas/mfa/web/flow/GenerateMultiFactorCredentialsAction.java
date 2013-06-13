package net.unicon.cas.mfa.web.flow;

import javax.validation.constraints.NotNull;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Credentials;
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

    private AuthenticationSupport authenticationSupport;

    public void setAuthenticationSupport(final AuthenticationSupport authSupport) {
        this.authenticationSupport = authSupport;
    }

    /**
     * Construct the {@link MultiFactorCredentials} instance by chaining current {@link Credentials}
     * and the {@link Authentication}.
     * @param context
     * @param upCredentials
     * @param id the identifier for the credentials used.
     * @return an instance of {@link MultiFactorCredentials}
     */
    public Credentials createCredentials(final RequestContext context, @NotNull final Credentials upCredentials, @NotNull final String id) {
        final Authentication authentication = getCasAuthentication(context);
        if (authentication == null || id == null || upCredentials == null) {
            return null;
        }

        final MultiFactorCredentials credentials = getMfaCredentialsInstanceFromContext(context);
        credentials.getChainedAuthentications().add(authentication);
        if (id != null && upCredentials != null) {
            credentials.getChainedCredentials().put(id, upCredentials);
        }

        MultiFactorRequestContextUtils.setMfaCredentials(context, credentials);
        return credentials;
    }

    /**
     * Obtain the {@link Authentication} object from the webflow's flow scope. If none,
     * attempt to obtain the authentication object from the current TGT.
     * @param context
     * @return the {@link Authentication} object
     */
    private Authentication getCasAuthentication(final RequestContext context) {

        final Authentication authentication = MultiFactorRequestContextUtils.getAuthentication(context);

        if (authentication == null) {
            final String tgt = MultiFactorRequestContextUtils.getTicketGrantingTicketId(context);
            if (!StringUtils.isBlank(tgt)) {
                return this.authenticationSupport.getAuthenticationFrom(tgt);
            }
        }

        return authentication;
    }

    private MultiFactorCredentials getMfaCredentialsInstanceFromContext(final RequestContext context) {
        final MultiFactorCredentials c = MultiFactorRequestContextUtils.getMfaCredentials(context);
        if (c == null) {
            return new MultiFactorCredentials();
        }
        return c;

    }
}
