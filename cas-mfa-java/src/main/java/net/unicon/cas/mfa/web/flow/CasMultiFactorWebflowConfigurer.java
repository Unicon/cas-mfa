package net.unicon.cas.mfa.web.flow;

import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import net.unicon.cas.mfa.web.support.UnrecognizedAuthenticationMethodException;
import org.apache.commons.lang.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.binding.convert.ConversionExecutor;
import org.springframework.binding.convert.service.RuntimeBindingConversionExecutor;
import org.springframework.binding.expression.EvaluationException;
import org.springframework.binding.expression.Expression;
import org.springframework.binding.expression.ExpressionParser;
import org.springframework.binding.expression.ParserContext;
import org.springframework.binding.expression.support.AbstractGetValueExpression;
import org.springframework.binding.expression.support.FluentParserContext;
import org.springframework.binding.expression.support.LiteralExpression;
import org.springframework.binding.mapping.Mapper;
import org.springframework.binding.mapping.impl.DefaultMapper;
import org.springframework.binding.mapping.impl.DefaultMapping;
import org.springframework.stereotype.Component;
import org.springframework.util.ClassUtils;
import org.springframework.webflow.action.EvaluateAction;
import org.springframework.webflow.action.ViewFactoryActionAdapter;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.ActionState;
import org.springframework.webflow.engine.DecisionState;
import org.springframework.webflow.engine.EndState;
import org.springframework.webflow.engine.Flow;
import org.springframework.webflow.engine.SubflowAttributeMapper;
import org.springframework.webflow.engine.SubflowState;
import org.springframework.webflow.engine.TargetStateResolver;
import org.springframework.webflow.engine.Transition;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;
import org.springframework.webflow.engine.support.DefaultTargetStateResolver;
import org.springframework.webflow.engine.support.DefaultTransitionCriteria;
import org.springframework.webflow.engine.support.GenericSubflowAttributeMapper;
import org.springframework.webflow.engine.support.TransitionExecutingFlowExecutionExceptionHandler;
import org.springframework.webflow.execution.Action;
import org.springframework.webflow.execution.ViewFactory;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Initialize the application context with the needed webflow mfa configuration
 * as much as possible to simplify adding mfa into an existing overlay.
 *
 * @author Misagh Moayyed
 */
@Component
public final class CasMultiFactorWebflowConfigurer implements InitializingBean {
    private static final Logger LOGGER = LoggerFactory.getLogger(CasMultiFactorWebflowConfigurer.class);

    private static final String FLOW_ID_LOGIN = "login";

    @Autowired
    private FlowBuilderServices flowBuilderServices;

    @Autowired
    private FlowDefinitionRegistry flowDefinitionRegistry;

    @Override
    @PostConstruct
    public void afterPropertiesSet() throws Exception {
        try {

            String[] flowIds = flowDefinitionRegistry.getFlowDefinitionIds();
            flowIds = (String[]) ArrayUtils.removeElement(flowIds, FLOW_ID_LOGIN);

            LOGGER.debug("Detected {} flow configurations: [{}]",
                    flowIds.length,
                    Arrays.toString(flowIds));

            LOGGER.debug("Configuring webflow for multifactor authentication...");
            setupWebflow(flowIds);
            LOGGER.debug("Configured webflow for multifactor authentication.");

        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    /**
     * Sets webflow.
     * @param flowIds the flow ids
     */

    private void setupWebflow(final String[] flowIds) {
        try {
            LOGGER.debug("Starting to configure webflow...");

            final Flow flow = (Flow) this.flowDefinitionRegistry.getFlowDefinition(FLOW_ID_LOGIN);
            LOGGER.debug("Retrieved flow id {} from flow definition registry", flow.getId());

            addTicketGrantingTicketExistsCheck(flow, flowIds);
            addMultiFactorOutcomeTransitionsToSubmissionActionState(flow, flowIds);
            addMultiFactorViewEndStates(flow);
            addMultiFactorGlobalTransitionsForExceptionHandling(flow);
            addOnEntryActionToServiceCheckState(flow);
            createMultiFactorSubflowStateDefinitions(flow, flowIds);
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
     * @param flowIds the flow ids
     */
    private void addMultiFactorOutcomeTransitionsToSubmissionActionState(final Flow flow, final String[] flowIds) {
        final ActionState actionState = (ActionState) flow.getState("realSubmit");
        LOGGER.debug("Retrieved action state {}", actionState.getId());

        final Action existingAction = actionState.getActionList().get(0);
        actionState.getActionList().remove(existingAction);

        final EvaluateAction action = createEvaluateAction("initiatingAuthenticationViaFormAction");
        actionState.getActionList().add(action);
        LOGGER.debug("Set action {} for action state {}", actionState.getId());

        for (final String flowId : flowIds) {
            addTransitionToActionState(actionState, flowId, flowId);
        }

    }

    /**
     * Add on entry action to service check state.
     *
     * @param flow the flow
     */
    private void addOnEntryActionToServiceCheckState(final Flow flow) {
        final DecisionState state = (DecisionState) flow.getState("serviceCheck");

        final EvaluateAction action = createEvaluateAction("removeHostnameServiceInContextAction");
        state.getEntryActionList().add(action);
        LOGGER.debug("Set on-entry action for decision state {}", state.getId());
    }
    /**
     * Create evaluate action.
     *
     * @param expression the expression
     * @return the evaluate action
     */
    private EvaluateAction createEvaluateAction(final String expression) {
        final ParserContext ctx = new FluentParserContext();
        final Expression action = this.flowBuilderServices.getExpressionParser()
                .parseExpression(expression, ctx);
        final EvaluateAction newAction = new EvaluateAction(action, null);

        LOGGER.debug("Created evaluate action for expression", action.getExpressionString());
        return newAction;
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
     * @param flowIds the flow ids
     */
    private void addTicketGrantingTicketExistsCheck(final Flow flow, final String[] flowIds) {
        try {
            final ActionState actionState = new ActionState(flow, "mfaTicketGrantingTicketExistsCheck");
            LOGGER.debug("Created action state {}", actionState.getId());
            actionState.getActionList().add(createEvaluateAction("validateInitialMfaRequestAction"));
            LOGGER.debug("Added action to the action state {} list of actions: {}", actionState.getId(), actionState.getActionList());

            for (final String flowId : flowIds) {
                addTransitionToActionState(actionState, flowId, flowId);
            }

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

    /**
     * Create multi factor subflow state definitions.
     *
     * @param flow the flow
     * @param flowIds the flow ids
     */
    private void createMultiFactorSubflowStateDefinitions(final Flow flow, final String[] flowIds) {
        createMultiFactorSubflowStateDefinitionsByAuthenticationMethod(flow, flowIds);
    }

    /**
     * Create multi factor parent subflow state definitions.
     *
     * @param flow the flow
     * @param id the id
     */
    private void createMultiFactorParentSubflowStateDefinitions(final Flow flow, final String id) {
        final EvaluateAction action = createEvaluateAction("generateMfaCredentialsAction");

        final SubflowState subflowState = createSubflowState(flow, id, id, action);

        final List<DefaultMapping> mappings = new ArrayList<DefaultMapping>();
        mappings.add(createMappingToSubflowState("mfaCredentials", "flowScope.mfaCredentials", true,
                MultiFactorCredentials.class));
        mappings.add(createMappingToSubflowState("mfaService", "flowScope.service", true,
                MultiFactorAuthenticationSupportingWebApplicationService.class));

        final Mapper inputMapper = createMapperToSubflowState(mappings);
        final SubflowAttributeMapper subflowMapper = createSubflowAttributeMapper(inputMapper, null);
        subflowState.setAttributeMapper(subflowMapper);

        subflowState.getTransitionSet().add(createTransition("mfaSuccess", "sendTicketGrantingTicket"));
        subflowState.getTransitionSet().add(createTransition("unknownPrincipalError", "viewUnknownPrincipalErrorView"));
        subflowState.getTransitionSet().add(createTransition("mfaUnrecognizedAuthnMethodError", "viewMfaUnrecognizedAuthnMethodErrorView"));
    }

    /**
     * Create multi factor subflow state definitions by authentication method.
     *
     * @param flow the flow
     * @param flowIds the flow ids
     */
    private void createMultiFactorSubflowStateDefinitionsByAuthenticationMethod(final Flow flow, final String[] flowIds) {
        for (final String flowId : flowIds) {
            createMultiFactorParentSubflowStateDefinitions(flow, flowId);
        }


    }

    /**
     * Create subflow state.
     *
     * @param flow the flow
     * @param id the id
     * @param subflow the subflow
     * @param entryAction the entry action
     * @return the subflow state
     */
    private SubflowState createSubflowState(final Flow flow, final String id, final String subflow,
                                            final Action entryAction) {

        final SubflowState state = new SubflowState(flow, id, new BasicSubflowExpression(subflow));
        if (entryAction != null) {
            state.getEntryActionList().add(entryAction);
        }

        return state;
    }

    /**
     * Create mapper to subflow state.
     *
     * @param mappings the mappings
     * @return the mapper
     */
    private Mapper createMapperToSubflowState(final List<DefaultMapping> mappings) {
        final DefaultMapper inputMapper = new DefaultMapper();
        for (final DefaultMapping mapping : mappings) {
            inputMapper.addMapping(mapping);
        }
        return inputMapper;
    }

    /**
     * Create mapping to subflow state.
     *
     * @param name the name
     * @param value the value
     * @param required the required
     * @param type the type
     * @return the default mapping
     */
    private DefaultMapping createMappingToSubflowState(final String name, final String value,
                                                       final boolean required, final Class type) {

        final ExpressionParser parser = this.flowBuilderServices.getExpressionParser();

        final Expression source = parser.parseExpression(value, new FluentParserContext());
        final Expression target = parser.parseExpression(name, new FluentParserContext());

        final DefaultMapping mapping = new DefaultMapping(source, target);
        mapping.setRequired(required);

        final ConversionExecutor typeConverter =
                new RuntimeBindingConversionExecutor(type, this.flowBuilderServices.getConversionService());
        mapping.setTypeConverter(typeConverter);
        return mapping;
    }

    /**
     * Create subflow attribute mapper.
     *
     * @param inputMapper the input mapper
     * @param outputMapper the output mapper
     * @return the subflow attribute mapper
     */
    private SubflowAttributeMapper createSubflowAttributeMapper(final Mapper inputMapper, final Mapper outputMapper) {
        return new GenericSubflowAttributeMapper(inputMapper, outputMapper);
    }

    private class BasicSubflowExpression extends AbstractGetValueExpression {
        private final String subflowId;

        /**
         * Instantiates a new Basic subflow expression.
         *
         * @param subflowId the subflow id
         */
        public BasicSubflowExpression(final String subflowId) {
            this.subflowId = subflowId;
        }

        @Override
        public Object getValue(final Object context) throws EvaluationException {
            return CasMultiFactorWebflowConfigurer.this.flowDefinitionRegistry.getFlowDefinition(this.subflowId);
        }
    }
}
