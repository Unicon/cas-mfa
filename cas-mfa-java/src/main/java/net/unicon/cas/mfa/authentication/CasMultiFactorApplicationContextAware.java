package net.unicon.cas.mfa.authentication;

import net.unicon.cas.mfa.web.flow.NoAuthenticationContextAvailable;
import net.unicon.cas.mfa.web.support.UnrecognizedAuthenticationMethodException;
import org.jasig.cas.authentication.AuthenticationManager;
import org.jasig.cas.web.support.ArgumentExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.binding.convert.ConversionExecutor;
import org.springframework.binding.expression.Expression;
import org.springframework.binding.expression.ParserContext;
import org.springframework.binding.expression.support.FluentParserContext;
import org.springframework.binding.expression.support.LiteralExpression;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;
import org.springframework.util.ClassUtils;
import org.springframework.webflow.action.EvaluateAction;
import org.springframework.webflow.action.ViewFactoryActionAdapter;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.ActionState;
import org.springframework.webflow.engine.EndState;
import org.springframework.webflow.engine.Flow;
import org.springframework.webflow.engine.TargetStateResolver;
import org.springframework.webflow.engine.Transition;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;
import org.springframework.webflow.engine.support.DefaultTargetStateResolver;
import org.springframework.webflow.engine.support.DefaultTransitionCriteria;
import org.springframework.webflow.engine.support.TransitionExecutingFlowExecutionExceptionHandler;
import org.springframework.webflow.execution.Action;
import org.springframework.webflow.execution.ViewFactory;

import javax.annotation.PostConstruct;
import java.util.List;

/**
 * Initialize the application context with the needed mfa configuratio
 * as much as possible to simplify adding mfa into an existing overlay.
 *
 * @author Misagh Moayyed
 */
@Component
public final class CasMultiFactorApplicationContextAware implements InitializingBean {
    private static final Logger LOGGER = LoggerFactory.getLogger(CasMultiFactorApplicationContextAware.class);

    @Autowired
    @Qualifier("builder")
    private FlowBuilderServices flowBuilderServices;

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    @Qualifier("authenticationManager")
    private AuthenticationManager authenticationManager;

    @Autowired
    @Qualifier("mfaRequestsCollectingArgumentExtractor")
    private ArgumentExtractor mfaRequestsCollectingArgumentExtractor;

    @Autowired
    private FlowDefinitionRegistry flowDefinitionRegistry;

    @Override
    @PostConstruct
    public void afterPropertiesSet() throws Exception {
        try {
            LOGGER.debug("Configuring application context for multifactor authentication...");
            addMultifactorArgumentExtractorConfiguration();
            LOGGER.debug("Configured application context for multifactor authentication.");

            LOGGER.debug("Configuring webflow for multifactor authentication...");
            setupWebflow();
            LOGGER.debug("Configured webflow for multifactor authentication.");

        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    /**
     * Add multifactor argument extractor configuration.
     */
    private void addMultifactorArgumentExtractorConfiguration() {
        LOGGER.debug("Configuring application context with [{}]",
                mfaRequestsCollectingArgumentExtractor.getClass().getName());

        final List<ArgumentExtractor> list = this.applicationContext.getBean("argumentExtractors", List.class);
        list.add(0, mfaRequestsCollectingArgumentExtractor);
    }

    /**
     * Sets webflow.
     */

    private void setupWebflow() {
        try {
            LOGGER.debug("Starting to configure webflow...");

            final Flow flow = (Flow) this.flowDefinitionRegistry.getFlowDefinition("login");
            LOGGER.debug("Retrieved flow id {} from flow definition registry", flow.getId());

            addTicketGrantingTicketExistsCheck(flow);
            addMultiFactorOutcomeTransitionsToSubmissionActionState(flow);
            addMultiFactorViewEndStates(flow);
            addMultiFactorGlobalTransitionsForExceptionHandling(flow);
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    /**
     * Add multi factor global transitions for exception handling.
     *
     * @param flow the flow
     */
    private void addMultiFactorGlobalTransitionsForExceptionHandling(final Flow flow) {
        addGlobalTransitionIfExceptionIsThrown(flow,
                "ticketGrantingTicketExistsCheck", NoAuthenticationContextAvailable.class);
        addGlobalTransitionIfExceptionIsThrown(flow,
                "viewMfaUnrecognizedAuthnMethodErrorView", UnrecognizedAuthenticationMethodException.class);
    }

    /**
     * Add global transition if exception is thrown.
     *
     * @param flow          the flow
     * @param targetStateId the target state id
     * @param clazz         the exception class
     */
    private void addGlobalTransitionIfExceptionIsThrown(final Flow flow, final String targetStateId, final Class<?> clazz) {

        try {
            final TransitionExecutingFlowExecutionExceptionHandler handler = new TransitionExecutingFlowExecutionExceptionHandler();
            final TargetStateResolver targetStateResolver = (TargetStateResolver) fromStringTo(TargetStateResolver.class)
                    .execute(targetStateId);
            handler.add(clazz, targetStateResolver);

            LOGGER.debug("Added transition {} to execute on the occurrence of {}", targetStateId, clazz.getName());
            flow.getExceptionHandlerSet().add(handler);
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }


    }

    /**
     * From string to class type, based on the flow conversion service.
     *
     * @param targetType the target type
     * @return the conversion executor
     */
    private ConversionExecutor fromStringTo(final Class targetType) {
        return this.flowBuilderServices.getConversionService().getConversionExecutor(String.class, targetType);
    }

    /**
     * Loads the specified class by name, either based on the conversion service
     * or by the flow classloader.
     *
     * @param name the name
     * @return the class
     */
    private Class toClass(final String name) {
        final Class clazz = this.flowBuilderServices.getConversionService().getClassForAlias(name);
        if (clazz != null) {
            return clazz;
        }

        try {
            final ClassLoader classLoader = this.flowBuilderServices.getApplicationContext().getClassLoader();
            return ClassUtils.forName(name, classLoader);
        } catch (final ClassNotFoundException e) {
            throw new IllegalArgumentException("Unable to load class '" + name + "'");
        }

    }

    /**
     * Add multi factor outcome transitions to submission action state.
     *
     * @param flow the flow
     */
    private void addMultiFactorOutcomeTransitionsToSubmissionActionState(final Flow flow) {
        final ActionState actionState = (ActionState) flow.getState("realSubmit");
        LOGGER.debug("Retrieved action state {}", actionState.getId());

        final Action existingAction = actionState.getActionList().get(0);
        actionState.getActionList().remove(existingAction);

        final ParserContext ctx = new FluentParserContext();
        final Expression action = this.flowBuilderServices.getExpressionParser()
                .parseExpression("initiatingAuthenticationViaFormAction", ctx);
        final EvaluateAction newAction = new EvaluateAction(action, null);
        actionState.getActionList().add(newAction);

        addTransitionToActionState(actionState, "mfa_strong_two_factor", "mfa_strong_two_factor");
        addTransitionToActionState(actionState, "mfa_sample_two_factor", "mfa_sample_two_factor");

    }

    /**
     * Add multi factor view end states.
     *
     * @param flow the flow
     */
    private void addMultiFactorViewEndStates(final Flow flow) {
        addEndStateBackedByView(flow, "viewMfaUnrecognizedAuthnMethodErrorView", "casMfaUnrecognizedAuthnMethodErrorView");
        addEndStateBackedByView(flow, "viewUnknownPrincipalErrorView", "casUnknownPrincipalErrorView");
    }

    /**
     * Add ticket granting ticket exists check.
     *
     * @param flow the flow
     */
    private void addTicketGrantingTicketExistsCheck(final Flow flow) {
        try {
            final ActionState actionState = new ActionState(flow, "mfaTicketGrantingTicketExistsCheck");
            LOGGER.debug("Created action state {}", actionState.getId());

            final Action action = this.applicationContext.getBean("validateInitialMfaRequestAction", Action.class);
            LOGGER.debug("Retrieved action {}", action.getClass());
            actionState.getActionList().add(action);
            LOGGER.debug("Added action to the action state {} list of actions: {}", actionState.getId(), actionState.getActionList());

            addTransitionToActionState(actionState, "mfa_strong_two_factor", "mfa_strong_two_factor");
            addTransitionToActionState(actionState, "mfa_sample_two_factor", "mfa_sample_two_factor");
            addTransitionToActionState(actionState, "requireTgt", "ticketGrantingTicketExistsCheck");

            flow.setStartState(actionState);
            LOGGER.debug("Replaced flow {} start state with {}", flow.getId(), flow.getStartState().getId());
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    /**
     * Add transition to action state.
     *
     * @param actionState     the action state
     * @param criteriaOutcome the criteria outcome
     * @param targetState     the target state
     */
    private void addTransitionToActionState(final ActionState actionState,
                                            final String criteriaOutcome, final String targetState) {
        try {
            final Transition transition = createTransition(criteriaOutcome, targetState);
            actionState.getTransitionSet().add(transition);

            LOGGER.debug("Added transition {} to the action state {}", transition.getId(), actionState.getId());
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    /**
     * Create transition.
     *
     * @param criteriaOutcome the criteria outcome
     * @param targetState     the target state
     * @return the transition
     */
    private Transition createTransition(final String criteriaOutcome, final String targetState) {
        final DefaultTransitionCriteria criteria = new DefaultTransitionCriteria(new LiteralExpression(criteriaOutcome));
        final DefaultTargetStateResolver resolver = new DefaultTargetStateResolver(targetState);

        return new Transition(criteria, resolver);
    }

    /**
     * Add end state backed by view.
     *
     * @param flow   the flow
     * @param id     the id
     * @param viewId the view id
     */
    private void addEndStateBackedByView(final Flow flow, final String id, final String viewId) {
        try {
            final EndState endState = new EndState(flow, id);
            final ViewFactory viewFactory = this.flowBuilderServices.getViewFactoryCreator().createViewFactory(
                    new LiteralExpression(viewId),
                    this.flowBuilderServices.getExpressionParser(),
                    this.flowBuilderServices.getConversionService(),
                    null, this.flowBuilderServices.getValidator());

            final Action finalResponseAction = new ViewFactoryActionAdapter(viewFactory);
            endState.setFinalResponseAction(finalResponseAction);
            LOGGER.debug("Created end state state {} on flow id {}, backed by view {}", id, flow.getId(), viewId);
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }
}
