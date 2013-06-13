package net.unicon.cas.mfa.web.support;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.web.support.AbstractSingleSignOutEnabledArgumentExtractor;

/**
 * The multifactor authentication argument extractor, responsible to
 * instruct CAS with the constructed instance of a {@link WebApplicationService}
 * that is supported based on the configured {@link #supportedAuthenticationMethods}.
 * @author Misagh Moayyed
 */
public final class MultiFactorAuthenticationArgumentExtractor extends AbstractSingleSignOutEnabledArgumentExtractor {

    private final List<String> supportedAuthenticationMethods;

    /**
     * Create an instance of {@link MultiFactorAuthenticationArgumentExtractor}.
     * @param authnMethods list of supported values for authentication method
     */
    public MultiFactorAuthenticationArgumentExtractor(final List<String> authnMethods) {
        this.supportedAuthenticationMethods = authnMethods;
    }

    @Override
    protected WebApplicationService extractServiceInternal(final HttpServletRequest request) {
        return DefaultMultiFactorAuthenticationSupportingWebApplicationService.createServiceFrom(request,
                getHttpClientIfSingleSignOutEnabled(), this.supportedAuthenticationMethods);
    }

}
