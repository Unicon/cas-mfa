package net.unicon.cas.mfa.authentication.handler;

import com.authy.AuthyApiClient;
import com.authy.api.Token;
import com.authy.api.Tokens;
import com.authy.api.User;
import com.authy.api.Users;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;
import org.apache.commons.lang.StringUtils;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.execution.RequestContextHolder;

import javax.validation.constraints.NotNull;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;


/**
 * @author Misagh Moayyed
 */
public final class AuthyAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthyAuthenticationHandler.class);

    private final AuthyApiClient authyClient;
    private final Users authyUsers;
    private final Tokens authyTokens;

    private String mailAttribute = "mail";
    private String phoneAttribute = "phone";
    private Boolean forceVerification = Boolean.FALSE;

    private AuthyUserAccountStore authyUserAccountStore = new InMemoryAuthyUserAccountStore();

    /**
     * Instantiates a new Authy authentication handler.
     *
     * @param apiKey the api key
     * @param apiUrl the api url
     * @throws MalformedURLException the malformed uRL exception
     */
    public AuthyAuthenticationHandler(@NotNull final String apiKey, @NotNull final String apiUrl) throws MalformedURLException {
        final URL url = new URL(apiUrl);
        final boolean testFlag = url.getProtocol().equals("http");

        this.authyClient = new AuthyApiClient(apiKey, apiUrl, testFlag);
        this.authyUsers = this.authyClient.getUsers();
        this.authyTokens = this.authyClient.getTokens();
    }

    @Override
    protected boolean authenticateUsernamePasswordInternal(final UsernamePasswordCredentials usernamePasswordCredentials)
            throws AuthenticationException {

        final RequestContext context = RequestContextHolder.getRequestContext();
        final Principal principal = MultiFactorRequestContextUtils.getMultiFactorPrimaryPrincipal(context);

        if (!this.authyUserAccountStore.contains(principal)) {
            final String email = (String) principal.getAttributes().get(this.mailAttribute);
            if (StringUtils.isBlank(email)) {
                throw new AuthyAuthenticationException("authy.registration.email.error", "No email address found for "
                        + principal.getId() , "emailError");
            }
            final String phone = (String) principal.getAttributes().get(this.phoneAttribute);
            if (StringUtils.isBlank(phone)) {
                throw new AuthyAuthenticationException("authy.registration.phone.error", "No phone number found for "
                        + principal.getId() , "phoneError");
            }

            final User user = authyUsers.createUser(phone, email);
            if (!user.isOk()) {
                 throw new AuthyAuthenticationException("authy.registration.error",
                         getAuthyErrorMessage(user.getError()), "error");
            }
            final long authyId = user.getId();
            this.authyUserAccountStore.add(authyId, principal);
        }

        final Long authyId = this.authyUserAccountStore.get(principal);

        final Map<String, String> options = new HashMap<String, String>();
        options.put("force", this.forceVerification.toString());

        final Token verification = this.authyTokens.verify(authyId.intValue(),
                usernamePasswordCredentials.getUsername(), options);

        if (!verification.isOk()) {
            throw new AuthyAuthenticationException("authy.verification.error",
                    getAuthyErrorMessage(verification.getError()), "error");
        }
        return true;
    }

    public void setMailAttribute(final String mailAttribute) {
        this.mailAttribute = mailAttribute;
    }

    public void setPhoneAttribute(final String phoneAttribute) {
        this.phoneAttribute = phoneAttribute;
    }

    public void setForceVerification(final Boolean forceVerification) {
        this.forceVerification = forceVerification;
    }

    public void setAuthyUserAccountStore(final AuthyUserAccountStore authyUserAccountStore) {
        this.authyUserAccountStore = authyUserAccountStore;
    }

    /**
     * Gets authy error message.
     *
     * @param err the err
     * @return the authy error message
     */
    private String getAuthyErrorMessage(final com.authy.api.Error err) {
        final StringBuilder builder = new StringBuilder();
        if (err != null) {
            builder.append("Authy Error");
            if (StringUtils.isNotBlank(err.getCountryCode())) {
                builder.append(": Country Code: " + err.getCountryCode());
            }
            if (StringUtils.isNotBlank(err.getMessage())) {
                builder.append(": Message: " + err.getMessage());
            }
        } else {
            builder.append("An unknown error has occurred. Check your API key and URL settings.");
        }
        return builder.toString();
    }

    private class AuthyAuthenticationException extends AuthenticationException {

        private static final long serialVersionUID = -1005618075810046279L;

        /**
         * Instantiates a new Authy authentication exception.
         *
         * @param code the code
         * @param msg the msg
         * @param type the type
         */
        public AuthyAuthenticationException(final String code, final String msg, final String type) {
            super(code, msg, type);
        }
    }
}
