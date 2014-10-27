package net.unicon.cas.mfa.web.flow.event;

import com.toopher.integrations.cas.authentication.handler.ToopherAuthenticationException;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * @author Misagh Moayyed
 */
public class ToopherErroringMultiFactorAuthenticationSpringWebflowEventBuilder
    extends ErroringMultiFactorAuthenticationSpringWebflowEventBuilder {

    @Override
    public Event buildEvent(final RequestContext context) {

        final ToopherAuthenticationException ex = MultiFactorRequestContextUtils
                .getAuthenticationExceptionInFlowScope(context, ToopherAuthenticationException.class);

        if (ex == null) {
            return super.buildEvent(context);
        }

        return new Event(this, ex.getType());
    }
}
