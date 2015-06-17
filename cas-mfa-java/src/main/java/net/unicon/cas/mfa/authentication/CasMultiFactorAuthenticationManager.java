package net.unicon.cas.mfa.authentication;

import org.jasig.cas.authentication.AbstractAuthentication;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationManager;
import org.jasig.cas.authentication.AuthenticationManagerImpl;
import org.jasig.cas.authentication.AuthenticationMetaDataPopulator;
import org.jasig.cas.authentication.ImmutableAuthentication;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.AuthenticationHandler;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.CredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Principal;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This is {@link CasMultiFactorAuthenticationManager} that delegates to the CAS authentication
 * manager and runs post-authn processes on the final object based on MFA requirements.
 *
 * @author Misagh Moayyed
 */
public class CasMultiFactorAuthenticationManager implements AuthenticationManager {
    private AuthenticationManager delegate;
    private List<AuthenticationHandler> authenticationHandlers = new ArrayList<>();
    private List<CredentialsToPrincipalResolver> credentialsToPrincipalResolvers = new ArrayList<>();
    private List<AuthenticationMetaDataPopulator> authenticationMetaDataPopulators = new ArrayList<>();

    public void setAuthenticationHandlers(final List<AuthenticationHandler> authenticationHandlers) {
        this.authenticationHandlers = authenticationHandlers;
    }

    public final void setAuthenticationMetaDataPopulators(final List<AuthenticationMetaDataPopulator> authenticationMetaDataPopulators) {
        this.authenticationMetaDataPopulators = authenticationMetaDataPopulators;
    }

    public void setCredentialsToPrincipalResolvers(final List<CredentialsToPrincipalResolver> credentialsToPrincipalResolvers) {
        this.credentialsToPrincipalResolvers = credentialsToPrincipalResolvers;
    }

    public void setDelegate(final AuthenticationManager delegate) {
        this.delegate = delegate;
    }

    @Override
    public Authentication authenticate(final Credentials credentials) throws AuthenticationException {
        final AuthenticationManagerImpl authImpl = new AuthenticationManagerImpl();
        authImpl.setAuthenticationHandlers(this.authenticationHandlers);
        authImpl.setCredentialsToPrincipalResolvers(this.credentialsToPrincipalResolvers);
        authImpl.setAuthenticationMetaDataPopulators(this.authenticationMetaDataPopulators);

        Authentication authentication = null;
        if (!this.authenticationHandlers.isEmpty()) {
            authentication = authImpl.authenticate(credentials);
        } else {
            authentication = this.delegate.authenticate(credentials);
        }

        MutableAuthentication authNMutable = new MutableAuthentication(authentication.getPrincipal(),
                authentication.getAttributes(), authentication.getAuthenticatedDate());
        for (final AuthenticationMetaDataPopulator authenticationMetaDataPopulator : this.authenticationMetaDataPopulators) {
            final Authentication modified = authenticationMetaDataPopulator.populateAttributes(authNMutable, credentials);
            authNMutable = new MutableAuthentication(modified.getPrincipal(),
                    modified.getAttributes(), modified.getAuthenticatedDate());
        }
        return new ImmutableAuthentication(authNMutable.getPrincipal(),
                authNMutable.getAttributes());

    }

    private final class MutableAuthentication extends AbstractAuthentication {
        private static final long serialVersionUID = 8051060297683763397L;

        private final Date authenticatedDate;

        /**
         * Instantiates a new Mutable authentication.
         *
         * @param principal the principal
         * @param attributes the attributes
         * @param date the date
         */
        public MutableAuthentication(final Principal principal, final Map<String, Object> attributes, final Date date) {
            super(principal, new HashMap<String, Object>(attributes));
            this.authenticatedDate = date;
        }

        public Date getAuthenticatedDate() {
            return this.authenticatedDate;
        }
    }
}
