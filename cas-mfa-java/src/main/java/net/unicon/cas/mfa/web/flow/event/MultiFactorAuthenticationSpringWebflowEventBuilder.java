package net.unicon.cas.mfa.web.flow.event;

import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * Describes the necessary mechanics for building multifactor event ids
 * for spring webflow from one transition to another.
 * @author Misagh Moayyed
 */
public interface MultiFactorAuthenticationSpringWebflowEventBuilder {

    /**
     * The Constant MFA_EVENT_ID_PREFIX.
     */
    String MFA_EVENT_ID_PREFIX = "mfa-";

    /**
     * Builds the MFA event required for the next transition to occur.
     *
     * @param context the context
     * @return the event
     * @throws java.lang.IllegalStateException if no matching transitions exists
     * for this particular event. Implementations may want to check the request context
     * for the validity of the configured event before passing it on.
     */
    Event buildEvent(RequestContext context);
}
