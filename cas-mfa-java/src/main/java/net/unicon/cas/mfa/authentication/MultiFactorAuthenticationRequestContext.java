package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import org.springframework.core.Ordered;

import javax.validation.constraints.NotNull;
import java.io.Serializable;

/**
 * Represents a single mfa request by wrapping {@link net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService}.
 * <p/>
 * Adds implementations of {@code equals} and {@code hashcode} to ensure the uniqueness of one mfa method per service per request origination source.
 * <p/>
 * Implements {@link org.springframework.core.Ordered} to assist implementations of
 * {@link net.unicon.cas.mfa.authentication.RequestedAuthenticationMethodRankingStrategy} do the ranking if they choose to use this abstraction.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public final class MultiFactorAuthenticationRequestContext implements Serializable, Ordered {

    private static final long serialVersionUID = 3895119051289676064L;

    private final MultiFactorAuthenticationSupportingWebApplicationService mfaService;

    private final int rank;

    /**
     * Ctor.
     *
     * @param mfaService target mfa service
     * @param rank the rank value of this request
     */
    public MultiFactorAuthenticationRequestContext(@NotNull final MultiFactorAuthenticationSupportingWebApplicationService mfaService,
                                                   final int rank) {
        this.mfaService = mfaService;
        //Treat zero or negative as undefined config value and make the request the lowest ranked?
        this.rank = (rank <= 0) ? Integer.MAX_VALUE : rank;
    }

    public MultiFactorAuthenticationSupportingWebApplicationService getMfaService() {
        return this.mfaService;
    }

    @Override
    public int getOrder() {
        return this.rank;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        final MultiFactorAuthenticationRequestContext that = (MultiFactorAuthenticationRequestContext) o;

        if (!this.getMfaService().getAuthenticationMethod().equals(that.getMfaService().getAuthenticationMethod())) {
            return false;
        }
        if (this.getMfaService().getAuthenticationMethodSource() != that.getMfaService().getAuthenticationMethodSource()) {
            return false;
        }
        if (!this.getMfaService().getId().equals(that.getMfaService().getId())) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int result = this.mfaService.getAuthenticationMethod().hashCode();
        result = 31 * result + (this.mfaService.getId().hashCode());
        result = 31 * result + (this.mfaService.getAuthenticationMethodSource().hashCode());
        return result;
    }

    @Override
    public String toString() {
        return String.format("MultiFactorAuthenticationRequestContext{ service={%s}, authn_method={%s}, source={%s} }",
                this.mfaService.getId(), this.mfaService.getAuthenticationMethod(), this.mfaService.getAuthenticationMethodSource());
    }
}
