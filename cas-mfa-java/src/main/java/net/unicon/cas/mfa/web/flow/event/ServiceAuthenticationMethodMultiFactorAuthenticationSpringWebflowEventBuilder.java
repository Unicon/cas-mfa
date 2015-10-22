package net.unicon.cas.mfa.web.flow.event;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import net.unicon.cas.mfa.web.support.UnrecognizedAuthenticationMethodException;
import org.jasig.cas.web.support.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.definition.TransitionDefinition;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * Builds an mfa event based on the authentication method captured by the service.
 * @author Misagh Moayyed
 */
public class ServiceAuthenticationMethodMultiFactorAuthenticationSpringWebflowEventBuilder
        implements MultiFactorAuthenticationSpringWebflowEventBuilder {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public Event buildEvent(final RequestContext context) {
        final MultiFactorAuthenticationSupportingWebApplicationService service = (MultiFactorAuthenticationSupportingWebApplicationService)
                WebUtils.getService(context);

        logger.debug("Attempting to build an event based on the authentication method [{}] and service [{}]",
                service.getAuthenticationMethod(), service.getId());
        final Event event = new Event(this, MFA_EVENT_ID_PREFIX + service.getAuthenticationMethod());
        logger.debug("Resulting event id is [{}]. Locating transitions in the context for that event id...",
                event.getId());

        final TransitionDefinition def = context.getMatchingTransition(event.getId());
        if (def == null) {
            logger.warn("Transition definition cannot be found for event [{}]", event.getId());
            throw new UnrecognizedAuthenticationMethodException(service.getAuthenticationMethod(), service.getId());
        }
        logger.debug("Found matching transition [{}] with target [{}] for event {}. Will proceed normally..",
            def.getId(), def.getTargetStateId(), event.getId());

        return event;
    }
}
