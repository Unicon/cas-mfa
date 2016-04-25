package net.unicon.cas.mfa.web.view;

import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import org.jasig.cas.CasProtocolConstants;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.services.RegisteredService;
import org.springframework.web.servlet.view.AbstractUrlBasedView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This is {@link Cas30ResponseView}.
 *
 * @author Misagh Moayyed
 */
public class Cas30ResponseView extends org.jasig.cas.web.view.Cas30ResponseView {
    private String authenticationMethodResponseAttribute;

    /**
     * Instantiates a new Cas 30 response view.
     *
     * @param view the view
     */
    protected Cas30ResponseView(final AbstractUrlBasedView view) {
        super(view);
    }

    @Override
    protected void prepareMergedOutputModel(final Map<String, Object> model, final HttpServletRequest request,
                                            final HttpServletResponse response) throws Exception {

        super.prepareMergedOutputModel(model, request, response);

        final Service service = super.getServiceFrom(model);
        final RegisteredService registeredService = this.servicesManager.findServiceBy(service);

        final Map<String, Object> attributes = new HashMap<>(getPrincipalAttributesAsMultiValuedAttributes(model));
        attributes.put(CasProtocolConstants.VALIDATION_CAS_MODEL_ATTRIBUTE_NAME_AUTHENTICATION_DATE,
                Collections.singleton(getAuthenticationDate(model)));
        attributes.put(CasProtocolConstants.VALIDATION_CAS_MODEL_ATTRIBUTE_NAME_FROM_NEW_LOGIN,
                Collections.singleton(isAssertionBackedByNewLogin(model)));
        attributes.put(CasProtocolConstants.VALIDATION_REMEMBER_ME_ATTRIBUTE_NAME,
                Collections.singleton(isRememberMeAuthentication(model)));

        decideIfCredentialPasswordShouldBeReleasedAsAttribute(attributes, model, registeredService);
        decideIfProxyGrantingTicketShouldBeReleasedAsAttribute(attributes, model, registeredService);

        attributes.put(this.authenticationMethodResponseAttribute,
                getAuthenticationAttribute(model, MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD));

        super.putIntoModel(model,
                CasProtocolConstants.VALIDATION_CAS_MODEL_ATTRIBUTE_NAME_ATTRIBUTES,
                this.casAttributeEncoder.encodeAttributes(attributes, getServiceFrom(model)));
    }

    public void setAuthenticationMethodResponseAttribute(final String authenticationMethodResponseAttribute) {
        this.authenticationMethodResponseAttribute = authenticationMethodResponseAttribute;
    }
}
