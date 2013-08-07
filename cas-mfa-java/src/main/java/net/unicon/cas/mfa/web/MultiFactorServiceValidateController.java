/*
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package net.unicon.cas.mfa.web;

import java.net.URL;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;

import net.unicon.cas.mfa.MultiFactorAuthenticationProtocolValidationSpecification;
import net.unicon.cas.mfa.ticket.UnacceptableMultiFactorAuthenticationMethodException;
import net.unicon.cas.mfa.ticket.UnrecognizedMultiFactorAuthenticationMethodException;
import net.unicon.cas.mfa.util.MultiFactorUtils;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.HttpBasedServiceCredentials;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.services.UnauthorizedServiceException;
import org.jasig.cas.ticket.TicketException;
import org.jasig.cas.ticket.TicketValidationException;
import org.jasig.cas.ticket.proxy.ProxyHandler;
import org.jasig.cas.validation.Assertion;
import org.jasig.cas.web.DelegateController;
import org.jasig.cas.web.support.ArgumentExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.ServletRequestDataBinder;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.servlet.ModelAndView;

/**
 * Process the /validate and /serviceValidate URL requests.
 * <p>
 * Obtain the Service Ticket and Service information and present them to the CAS
 * validation services. Receive back an Assertion containing the user Principal
 * and (possibly) a chain of Proxy Principals. Store the Assertion in the Model
 * and chain to a View to generate the appropriate response (CAS 1, CAS 2 XML,
 * SAML, ...).
 *
 * <p>This implementation differs from the default, in that the validation of
 * the incoming request is handled by an instance of
 * {@link MultiFactorAuthenticationProtocolValidationSpecification}. Validation
 * errors are signaled back to this controller via exceptions, the result of which
 * are passed down to the error view.
 *
 * <p>This extension, additionally, will also attempt to map the validation parameter
 * {@link MultiFactorAuthenticationSupportingWebApplicationService#CONST_PARAM_AUTHN_METHOD}
 * in order to activate validation of mfa requests. Otherwise, it's compliant with the default
 * implementation.
 * @author Scott Battaglia
 * @author Misagh Moayyed
 * @since 3.0
 */
public class MultiFactorServiceValidateController extends DelegateController {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    /** View if Service Ticket Validation Fails. */
    private static final String DEFAULT_SERVICE_FAILURE_VIEW_NAME = "casServiceFailureView";

    /** View if Service Ticket Validation Succeeds. */
    private static final String DEFAULT_SERVICE_SUCCESS_VIEW_NAME = "casServiceSuccessView";

    /** Constant representing the PGTIOU in the model. */
    private static final String MODEL_PROXY_GRANTING_TICKET_IOU = "pgtIou";

    /** Constant representing the Assertion in the model. */
    private static final String MODEL_ASSERTION = "assertion";

    /** Constant representing the authentication method in the model. */
    private static final String MODEL_AUTHN_METHOD = MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD;

    /** The CORE which we will delegate all requests to. */
    @NotNull
    private CentralAuthenticationService centralAuthenticationService;

    /** The validation protocol we want to use. */
    @NotNull
    private MultiFactorAuthenticationProtocolValidationSpecification validationSpecificationClass
            = new MultiFactorAuthenticationProtocolValidationSpecification();

    /** The proxy handler we want to use with the controller. */
    @NotNull
    private ProxyHandler proxyHandler;

    /** The view to redirect to on a successful validation. */
    @NotNull
    private String successView = DEFAULT_SERVICE_SUCCESS_VIEW_NAME;

    /** The view to redirect to on a validation failure. */
    @NotNull
    private String failureView = DEFAULT_SERVICE_FAILURE_VIEW_NAME;

    /** Extracts parameters from Request object. */
    @NotNull
    private ArgumentExtractor argumentExtractor;

    /**
     * Overrideable method to determine which credentials to use to grant a
     * proxy granting ticket. Default is to use the pgtUrl.
     *
     * @param request the HttpServletRequest object.
     * @return the credentials or null if there was an error or no credentials
     * provided.
     */
    protected final Credentials getServiceCredentialsFromRequest(final HttpServletRequest request) {
        final String pgtUrl = request.getParameter("pgtUrl");
        if (StringUtils.isNotBlank(pgtUrl)) {
            try {
                return new HttpBasedServiceCredentials(new URL(pgtUrl));
            } catch (final Exception e) {
                logger.error("Error constructing pgtUrl", e);
            }
        }

        return null;
    }

    /**
     * Initialize the binder with the required fields.
     * @param request the request object
     * @param binder  the binder instance
     */
    protected final void initBinder(final HttpServletRequest request, final ServletRequestDataBinder binder) {
        binder.setRequiredFields("renew");
    }

    /**
     * <p>Handle the request. Specially, abides by the default behavior specified in the {@link ServiceValidateController}
     * and then, invokes the {@link #getCommandClass()} method to delegate the task of spec validation.
     * @param request request object
     * @param response response object
     * @return A {@link ModelAndView} object pointing to either {@link #setSuccessView(String)} or {@link #setFailureView(String)}
     * @throws Exception In case the authentication method cannot be retrieved by the binder from the incoming request.
     */
    @Override
    protected final ModelAndView handleRequestInternal(final HttpServletRequest request, final HttpServletResponse response)
            throws Exception {
        final WebApplicationService service = this.argumentExtractor.extractService(request);
        final String serviceTicketId = service != null ? service.getArtifactId() : null;

        if (service == null || serviceTicketId == null) {
            logger.debug(String.format("Could not process request; Service: %s, Service Ticket Id: %s", service, serviceTicketId));
            return generateErrorView("INVALID_REQUEST", "INVALID_REQUEST", null);
        }

        try {
            final Credentials serviceCredentials = getServiceCredentialsFromRequest(request);
            String proxyGrantingTicketId = null;

            if (serviceCredentials != null) {
                try {
                    proxyGrantingTicketId = this.centralAuthenticationService.delegateTicketGrantingTicket(serviceTicketId,
                            serviceCredentials);
                } catch (final TicketException e) {
                    logger.error("TicketException generating ticket for: " + serviceCredentials, e);
                }
            }

            final Assertion assertion = this.centralAuthenticationService.validateServiceTicket(serviceTicketId, service);

            final MultiFactorAuthenticationProtocolValidationSpecification validationSpecification = this.getCommandClass();
            final ServletRequestDataBinder binder = new ServletRequestDataBinder(validationSpecification, "validationSpecification");
            initBinder(request, binder);
            binder.bind(request);

            /**
             * The binder does not support field aliases. This means that the request parameter names
             * must exactly match the validation spec fields, or the match fails. Since the validation request
             * per the modified protocol will use 'authn_method', we could either create a matching field
             * inside the validation object, create a custom data binder object that does the conversion,
             * or simply bind the parameter manually.
             *
             * This implementation opts for the latter choice.
             */
            final String authnMethod = ServletRequestUtils.getStringParameter(request,
                    MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD);
            validationSpecification.setAuthenticationMethod(authnMethod);

            try {
                if (!validationSpecification.isSatisfiedBy(assertion)) {
                    logger.debug("ServiceTicket [" + serviceTicketId + "] does not satisfy validation specification.");
                    return generateErrorView("INVALID_TICKET", "INVALID_TICKET_SPEC", null);
                }
            } catch (final UnrecognizedMultiFactorAuthenticationMethodException e) {
                logger.debug(e.getMessage(), e);
                return generateErrorView(e.getCode(), e.getMessage(), new Object[] {e.getAuthenticationMethod()});
            } catch (final UnacceptableMultiFactorAuthenticationMethodException e) {
                logger.debug(e.getMessage(), e);
                return generateErrorView(e.getCode(), e.getMessage(), new Object[] {serviceTicketId, e.getAuthenticationMethod()});
            }

            onSuccessfulValidation(serviceTicketId, assertion);

            final ModelAndView success = new ModelAndView(this.successView);
            success.addObject(MODEL_ASSERTION, assertion);

            if (serviceCredentials != null && proxyGrantingTicketId != null) {
                final String proxyIou = this.proxyHandler.handle(serviceCredentials, proxyGrantingTicketId);
                success.addObject(MODEL_PROXY_GRANTING_TICKET_IOU, proxyIou);
            }

            final String authnMethods = MultiFactorUtils.getFulfilledAuthenticationMethodsAsString(assertion);
            if (StringUtils.isNotBlank(authnMethods)) {
                success.addObject(MODEL_AUTHN_METHOD, authnMethods);
            }
            logger.debug(String.format("Successfully validated service ticket: %s", serviceTicketId));

            return success;
        } catch (final TicketValidationException e) {
            return generateErrorView(e.getCode(), e.getCode(),
                    new Object[] {serviceTicketId, e.getOriginalService().getId(), service.getId()});
        } catch (final TicketException te) {
            return generateErrorView(te.getCode(), te.getCode(), new Object[] {serviceTicketId});
        } catch (final UnauthorizedServiceException e) {
            return generateErrorView(e.getMessage(), e.getMessage(), null);
        }
    }

    /**
     * Template method to handle post successful validation event by extensions.
     * @param serviceTicketId service ticket in validation
     * @param assertion the assertion generated after validation
     */
    protected void onSuccessfulValidation(final String serviceTicketId, final Assertion assertion) {
        // template method with nothing to do.
    }

    /**
     * Generate the error view to indicate a failed validation event.
     * @param code  the error code
     * @param description error description
     * @param args additional values associated with the error, passed down to the message source
     * @return A {@link ModelAndView} based on {@link #setFailureView(String)}
     */
    private ModelAndView generateErrorView(final String code, final String description, final Object[] args) {
        final ModelAndView modelAndView = new ModelAndView(this.failureView);
        final String convertedDescription = getMessageSourceAccessor().getMessage(code, args, description);
        modelAndView.addObject("code", code);
        modelAndView.addObject("description", convertedDescription);

        return modelAndView;
    }

    /**
     * Returns the instance of {@link MultiFactorAuthenticationProtocolValidationSpecification} that is responsible
     * to validate the incoming validation request based on the augmented spec for MFA.
     * @return the instance of {@link MultiFactorAuthenticationProtocolValidationSpecification}
     */
    private MultiFactorAuthenticationProtocolValidationSpecification getCommandClass() {
        try {
            return this.validationSpecificationClass;
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final boolean canHandle(final HttpServletRequest request, final HttpServletResponse response) {
        return true;
    }

    /**
     * @param centralAuthenticationService The centralAuthenticationService to
     * set.
     */
    public final void setCentralAuthenticationService(final CentralAuthenticationService centralAuthenticationService) {
        this.centralAuthenticationService = centralAuthenticationService;
    }

    public final void setArgumentExtractor(final ArgumentExtractor argumentExtractor) {
        this.argumentExtractor = argumentExtractor;
    }

    /**
     * @param validationSpecificationClass The authenticationSpecificationClass
     * to set.
     */
    public final void setValidationSpecificationClass(
            final MultiFactorAuthenticationProtocolValidationSpecification validationSpecificationClass) {
        this.validationSpecificationClass = validationSpecificationClass;
    }

    /**
     * @param failureView The failureView to set.
     */
    public final void setFailureView(final String failureView) {
        this.failureView = failureView;
    }

    /**
     * @param successView The successView to set.
     */
    public final void setSuccessView(final String successView) {
        this.successView = successView;
    }

    /**
     * @param proxyHandler The proxyHandler to set.
     */
    public final void setProxyHandler(final ProxyHandler proxyHandler) {
        this.proxyHandler = proxyHandler;
    }

}
