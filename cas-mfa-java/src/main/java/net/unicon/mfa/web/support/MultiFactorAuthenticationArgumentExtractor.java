package net.unicon.mfa.web.support;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.web.support.AbstractSingleSignOutEnabledArgumentExtractor;

/**
 * The multifactor authentication argument extractor.
 * @author Misagh Moayyed
 *
 */
public final class MultiFactorAuthenticationArgumentExtractor extends AbstractSingleSignOutEnabledArgumentExtractor {

    private final List<String> supportedLevelsOfAuthentication;

    public MultiFactorAuthenticationArgumentExtractor(final List<String> listOfLOAs) {
        this.supportedLevelsOfAuthentication = listOfLOAs;
    }

    @Override
    protected WebApplicationService extractServiceInternal(final HttpServletRequest request) {
        return MultiFactorAuthenticationService.createServiceFrom(request,
                getHttpClientIfSingleSignOutEnabled(), this.supportedLevelsOfAuthentication);
    }

}
