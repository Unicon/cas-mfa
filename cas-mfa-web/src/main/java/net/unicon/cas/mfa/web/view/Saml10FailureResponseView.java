package net.unicon.cas.mfa.web.view;

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
import java.util.Map;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.web.view.AbstractSaml10ResponseView;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.StatusCode;

/**
 * Represents a failed attempt at validating a ticket, responding via a SAML SOAP message.
 *
 * @author Misagh Moayyed
 */
public final class Saml10FailureResponseView extends AbstractSaml10ResponseView {

    @Override
    protected void prepareResponse(final Response response, final Map<String, Object> model) {
        String statusMessage = (String) model.get("description");
        final String authnMethod = (String) model.get(MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD);

        if (StringUtils.isNotBlank(authnMethod)) {
            statusMessage += MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD
                         + "=" + authnMethod;
        }
        response.setStatus(newStatus(StatusCode.REQUEST_DENIED, statusMessage));
    }
}
