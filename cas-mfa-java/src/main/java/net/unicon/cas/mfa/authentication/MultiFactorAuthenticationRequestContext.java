package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.springframework.core.Ordered;

import javax.validation.constraints.NotNull;
import java.io.Serializable;

/**
 * Represents a single mfa request by wrapping
 * {@link net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService}.
 * <p/>
 * Adds implementations of {@code equals} and {@code hashcode} to ensure the uniqueness of
 * one mfa method per service per request origination source.
 * <p/>
 * Implements {@link org.springframework.core.Ordered} to assist implementations of
 * {@link net.unicon.cas.mfa.authentication.RequestedAuthenticationMethodRankingStrategy} do
 * the ranking if they choose to use this abstraction.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public final class MultiFactorAuthenticationRequestContext implements Serializable, Ordered {

    private static final long serialVersionUID = 3895119051289676064L;

    private final MultiFactorAuthenticationSupportingWebApplicationService mfaService;

    private final int rank;

    /**
     * Ctor. Treats zero or negative rank as undefined
     *
     * @param mfaService target mfa service
     * @param rank the rank value of this request
     */
    public MultiFactorAuthenticationRequestContext(@NotNull final MultiFactorAuthenticationSupportingWebApplicationService mfaService,
                                                   final int rank) {
        this.mfaService = mfaService;
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
        return this.getMfaService().equals(that.getMfaService());
    }

    @Override
    public int hashCode() {
        final HashCodeBuilder builder = new HashCodeBuilder(13, 133);
        return builder.append(this.mfaService.getAuthenticationMethod())
                      .append(this.mfaService.getId())
                      .append(this.mfaService.getAuthenticationMethodSource())
                      .toHashCode();
    }

    @Override
    public String toString() {
        final ToStringBuilder builder = new ToStringBuilder(ToStringStyle.DEFAULT_STYLE);
        return builder.append(this.mfaService.getId())
               .append(this.mfaService.getAuthenticationMethod())
               .append(this.mfaService.getAuthenticationMethodSource())
               .toString();
    }
}
