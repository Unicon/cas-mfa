package net.unicon.cas.mfa.web.flow.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * Builds the error event on MFA ops.
 * @author Misagh Moayyed
 */
public class ErroringMultiFactorAuthenticationSpringWebflowEventBuilder
    implements MultiFactorAuthenticationSpringWebflowEventBuilder {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * The Constant MFA_ERROR_EVENT_ID.
     */
    public static final String MFA_ERROR_EVENT_ID = "error";

    @Override
    public Event buildEvent(final RequestContext context) {
        logger.debug("Building event id {}", MFA_ERROR_EVENT_ID);
        return new Event(this, MFA_ERROR_EVENT_ID);
    }
}
