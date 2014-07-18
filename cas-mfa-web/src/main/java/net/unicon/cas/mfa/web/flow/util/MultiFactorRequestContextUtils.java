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
package net.unicon.cas.mfa.web.flow.util;

import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationTransactionContext;
import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

import org.jasig.cas.authentication.Authentication;
import org.springframework.webflow.execution.RequestContext;

/**
 * Utility methods that facilitate retrieval and storage of MFA objects inside {@link RequestContext}.
 *
 * @author Misagh Moayyed
 */
public final class MultiFactorRequestContextUtils {

    /**
     * Attribute name by which the authentication context can be retrieved/placed in the flow.
     */
    public static final String CAS_AUTHENTICATION_ATTR_NAME = "casAuthentication";

    /**
     * Attribute name by which the TGT can be retrieved/placed in the flow.
     */
    public static final String CAS_TICKET_GRANTING_TICKET_ATTR_NAME = "ticketGrantingTicketId";

    /**
     * Attribute name by which the MFA credentials can be retrieved/placed in the flow.
     */
    public static final String CAS_MFA_CREDENTIALS_ATTR_NAME = "mfaCredentials";

    /**
     * Attribute name by which the required authentication method can be retrieved/placed in the flow.
     */
    public static final String CAS_MFA_REQ_AUTHN_METHOD = "requiredAuthenticationMethod";

    /**
     * Instantiates a new multi factor request context utils.
     */
    private MultiFactorRequestContextUtils() {
    }

    /**
     * Gets the mfa credentials.
     *
     * @param context the context
     *
     * @return the mfa credentials
     */
    public static MultiFactorCredentials getMfaCredentials(final RequestContext context) {
        return (MultiFactorCredentials) context.getFlowScope().get(CAS_MFA_CREDENTIALS_ATTR_NAME);
    }

    /**
     * Gets the ticket granting ticket id.
     *
     * @param context the context
     *
     * @return the ticket granting ticket id
     */
    public static String getTicketGrantingTicketId(final RequestContext context) {
        return (String) context.getFlowScope().get(CAS_TICKET_GRANTING_TICKET_ATTR_NAME);
    }

    /**
     * Gets the authentication.
     *
     * @param context the context
     *
     * @return the authentication
     */
    public static Authentication getAuthentication(final RequestContext context) {
        return (Authentication) context.getFlowScope().get(CAS_AUTHENTICATION_ATTR_NAME);
    }

    /**
     * Sets the mfa credentials.
     *
     * @param context the context
     * @param credentials the credentials
     */
    public static void setMfaCredentials(final RequestContext context, final MultiFactorCredentials credentials) {
        context.getFlowScope().put(CAS_MFA_CREDENTIALS_ATTR_NAME, credentials);
    }

    /**
     * Sets the authentication.
     *
     * @param context the context
     * @param auth the auth
     */
    public static void setAuthentication(final RequestContext context, final Authentication auth) {
        context.getFlowScope().put(CAS_AUTHENTICATION_ATTR_NAME, auth);
    }

    /**
     * Sets the ticket granting ticket id.
     *
     * @param context the context
     * @param tgtId the tgt id
     */
    public static void setTicketGrantingTicketId(final RequestContext context, final String tgtId) {
        context.getFlowScope().put(CAS_TICKET_GRANTING_TICKET_ATTR_NAME, tgtId);
    }

    /**
     * Sets the required authentication method.
     *
     * @param context the context
     * @param requiredAuthenticationMethod the required authentication method
     */
    public static void setRequiredAuthenticationMethod(final RequestContext context, final String requiredAuthenticationMethod) {
        context.getFlowScope().put(CAS_MFA_REQ_AUTHN_METHOD, requiredAuthenticationMethod);
    }

    /**
     * Get required authentication method from flow scope.
     *
     * @param context the context
     *
     * @return authentication method or null
     */
    public static String getRequiredAuthenticationMethod(final RequestContext context) {
        return String.class.cast(context.getFlowScope().get(CAS_MFA_REQ_AUTHN_METHOD));
    }

    /**
     * Sets the multifactor web application service.
     *
     * @param context the context
     * @param svc the svc
     */
    public static void setMultifactorWebApplicationService(final RequestContext context,
                                                           final MultiFactorAuthenticationSupportingWebApplicationService svc) {
        context.getFlowScope().put("service", svc);
    }

    /**
     * Get mfa service from flow scope.
     *
     * @param context the context
     *
     * @return mfa service or null
     */
    public static MultiFactorAuthenticationSupportingWebApplicationService
                            getMultifactorWebApplicationService(final RequestContext context) {
        final Object svc = context.getFlowScope().get("service");
        return ((svc != null) && (svc instanceof MultiFactorAuthenticationSupportingWebApplicationService))
                ? MultiFactorAuthenticationSupportingWebApplicationService.class.cast(svc)
                : null;
    }

    /**
     * Fetch {@link net.unicon.cas.mfa.authentication.MultiFactorAuthenticationTransactionContext} from flow scope.
     *
     * @param context the context
     *
     * @return mfa transaction or null
     */
    public static MultiFactorAuthenticationTransactionContext getMfaTransaction(final RequestContext context) {
        return MultiFactorAuthenticationTransactionContext.class
                .cast(context.getConversationScope().get(MultiFactorAuthenticationTransactionContext.class.getSimpleName()));
    }

    /**
     * Set mfa transaction into conversation scope.
     *
     * @param context the context
     * @param mfaTransaction ths mfa transaction
     */
    public static void setMfaTransaction(final RequestContext context,
                                         final MultiFactorAuthenticationTransactionContext mfaTransaction) {
        context.getConversationScope().put(MultiFactorAuthenticationTransactionContext.class.getSimpleName(), mfaTransaction);
    }
}
