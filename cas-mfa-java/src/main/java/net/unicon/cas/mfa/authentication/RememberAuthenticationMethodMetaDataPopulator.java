package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationMetaDataPopulator;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.web.support.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.execution.RequestContextHolder;

/**
 * Remember the authentication method used for the retrieved instance of
 * {@link MultiFactorAuthenticationSupportingWebApplicationService}. The
 * method will be placed into the authentication context as an attribute,
 * remembered by {@link MultiFactorAuthenticationSupportingWebApplicationService#CONST_PARAM_AUTHN_METHOD}.
 * @author Misagh Moayyed
 */
public class RememberAuthenticationMethodMetaDataPopulator implements AuthenticationMetaDataPopulator {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public final Authentication populateAttributes(final Authentication authentication, final Credentials credentials) {

        final RequestContext context = RequestContextHolder.getRequestContext();
        if (context != null) {
            final Service svc = WebUtils.getService(context);

            if (svc instanceof MultiFactorAuthenticationSupportingWebApplicationService) {
                final MultiFactorAuthenticationSupportingWebApplicationService mfaSvc =
                        (MultiFactorAuthenticationSupportingWebApplicationService) svc;

                authentication.getAttributes().put(
                        MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD,
                        mfaSvc.getAuthenticationMethod());

                logger.debug("Captured authentication method [{}] into the authentation context",
                        mfaSvc.getAuthenticationMethod());
            }
        }
        return authentication;
    }
}
