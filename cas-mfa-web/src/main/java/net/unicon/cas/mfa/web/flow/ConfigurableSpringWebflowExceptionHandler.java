package net.unicon.cas.mfa.web.flow;

import org.springframework.webflow.engine.support.TransitionExecutingFlowExecutionExceptionHandler;

/**
 * A extension of {@link TransitionExecutingFlowExecutionExceptionHandler} that exposes configuration
 * for convenience directly via a constructor, such that handlers can be configured via explicit spring beans.
 * @author Misagh Moayyed
 */
public final class ConfigurableSpringWebflowExceptionHandler extends TransitionExecutingFlowExecutionExceptionHandler {

    /**
     * Initialize the handler with the exception class to handle, and the state to which the flow must move.
     * @param exceptionClass exception class to handle
     * @param state state to which the flow moves.
     */
    public ConfigurableSpringWebflowExceptionHandler(final Class<Exception> exceptionClass, final String state) {
        super();
        add(exceptionClass, state);
    }
}
