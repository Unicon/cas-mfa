package net.unicon.cas.mfa.web.flow.event;

import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * Builds the error event on MFA ops.
 * @author Misagh Moayyed
 */
public class ErroringMultiFactorAuthenticationSpringWebflowEventBuilder
    implements MultiFactorAuthenticationSpringWebflowEventBuilder {
    /**
     * The Constant MFA_ERROR_EVENT_ID.
     */
    public static final String MFA_ERROR_EVENT_ID = "error";

    @Override
    public Event buildEvent(final RequestContext context) {
        return new Event(this, MFA_ERROR_EVENT_ID);
    }
}
