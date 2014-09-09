package net.unicon.cas.mfa.web;

import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * Check the context to see if the service available is the {@link #hostname}.
 * If it is, remove the service so a service ticket wouldn't be created. This
 * is only used in cases where a service is not specified upon logging into
 * CAS, and in order for principal attributes to evaluate the authentication
 * and step through mfa, a service that is the hostname, that is CAS itself
 * is specified in order to allow for mfa based on principal attributes.
 * Since this "dummy" service is only used for that particular sequence,
 * it needs to be removed from the context so further actions in the flow
 * don't consider it a valid service deserving of an ST.
 * @author Misagh Moayyed
 */
public final class CheckHostnameInContextAction  extends AbstractAction {
    private final String hostname;

    /**
     * Instantiates a new Check hostname in context action.
     *
     * @param hostname the hostname
     */
    public CheckHostnameInContextAction(final String hostname) {
        this.hostname = hostname;
    }

    @Override
    protected Event doExecute(final RequestContext context) throws Exception {
        final MultiFactorAuthenticationSupportingWebApplicationService svc =
                MultiFactorRequestContextUtils.getMultifactorWebApplicationService(context);
        if (svc != null && svc.getId().equals(this.hostname)) {
            MultiFactorRequestContextUtils.setMultifactorWebApplicationService(context, null);
        }

        return null;
    }
}
