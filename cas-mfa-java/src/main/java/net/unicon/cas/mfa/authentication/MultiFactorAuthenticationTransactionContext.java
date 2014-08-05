package net.unicon.cas.mfa.authentication;

import org.jasig.cas.authentication.Authentication;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService.AuthenticationMethodSource;

/**
 * Class holding contextual information pertaining to any currently in-progress mfa authentication transactions i.e.
 * mfa methods from multiple definition sources required to authenticate against any current target service collected for just current authentication request.
 * Each new authentication request should represent a new mfa transaction.
 * <p/>
 * This class enforces invariants that ensures that only a single target service is able to participate
 * in such a single mfa authentication transaction
 * and only a single instance of the same authentication method source could exist at a time.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public final class MultiFactorAuthenticationTransactionContext implements Serializable {


    private final String targetServiceId;

    /**
     * Primary authentication if has been accomplished OR null.
     */
    private Authentication primaryAuthentication;

    /**
     * A collection of mfa requests or empty if none.
     */
    private Set<MultiFactorAuthenticationRequestContext> mfaRequests = new HashSet<MultiFactorAuthenticationRequestContext>();


    /**
     * Ctor.
     *
     * @param targetServiceId target service
     */
    public MultiFactorAuthenticationTransactionContext(final String targetServiceId) {
        Assert.notNull(targetServiceId, "targetServiceId cannot be null");
        this.targetServiceId = targetServiceId;
    }

    /**
     * Get.
     *
     * @return primary authentication.
     */
    public Authentication getPrimaryAuthentication() {
        return primaryAuthentication;
    }


    /**
     * Setter that supports fluid API.
     *
     * @param primaryAuthentication primaryAuthentication
     *
     * @return this
     */
    public MultiFactorAuthenticationTransactionContext setPrimaryAuthentication(final Authentication primaryAuthentication) {
        this.primaryAuthentication = primaryAuthentication;
        return this;
    }

    /**
     * Get.
     *
     * @return current mfa requests
     */
    public Set<MultiFactorAuthenticationRequestContext> getMfaRequests() {
        return Collections.unmodifiableSet(mfaRequests);
    }

    /**
     * Get.
     *
     * @return target service id
     */
    public String getTargetServiceId() {
        return targetServiceId;
    }

    /**
     * Add mfa request to internal collection. Supports fluid API.
     *
     * @param mfaRequest mfaRequest
     *
     * @return this
     */
    public MultiFactorAuthenticationTransactionContext addMfaRequest(final MultiFactorAuthenticationRequestContext mfaRequest) {
        if (differentThanTargetService(mfaRequest.getMfaService().getId())) {
            throw new IllegalArgumentException(String.format("Requested mfa target service {%s} is different from "
                            + "the current authentication transaction target service {%s}",
                    mfaRequest.getMfaService().getId(), this.targetServiceId));
        }
        if (authnMethodSourceAlreadyExists(mfaRequest.getMfaService().getAuthenticationMethodSource())) {
            throw new IllegalArgumentException(String.format("Requested mfa method source {%s} already exists",
                    mfaRequest.getMfaService().getAuthenticationMethodSource()));
        }
        this.mfaRequests.add(mfaRequest);
        return this;
    }

    /**
     * Is the current tx's target service different from a given one.
     *
     * @param serviceId passed in service id
     *
     * @return true if the passed in service is different from the current tx's target service
     */
    private boolean differentThanTargetService(final String serviceId) {
        return !(this.targetServiceId.equals(serviceId));
    }

    /**
     * Is there an authentication method source already captured that equals to the incoming one.
     *
     * @param authenticationMethodSource incoming authenticationMethodSource
     *
     * @return true if authn method already exists and false otherwise
     */
    private boolean authnMethodSourceAlreadyExists(final AuthenticationMethodSource authenticationMethodSource) {
        if (this.mfaRequests.isEmpty()) {
            return false;
        }
        for (MultiFactorAuthenticationRequestContext ctx : this.mfaRequests) {
            if (ctx.getMfaService().getAuthenticationMethodSource() == authenticationMethodSource) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String toString() {
        return "MultiFactorAuthenticationTransactionContext{"
                +
                "targetServiceId='" + targetServiceId + '\''
                +
                ", primaryAuthentication=" + primaryAuthentication
                +
                ", mfaRequests=" + mfaRequests
                +
                '}';
    }
}
