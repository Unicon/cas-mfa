package net.unicon.cas.mfa.web.flow.view;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.authentication.principal.Principal;

/**
 * Greets the principal by a configurable principal attribute and falls back
 * to the principal id, if none is found.
 * @author Misagh Moayyed
 */
public class MultifactorLoginViewPrincipalAttributeGreeter implements MultiFactorLoginViewPrincipalGreeter {

    private final String greetingAttributeName;

    public MultifactorLoginViewPrincipalAttributeGreeter(final String greetingAttrName) {
        this.greetingAttributeName = greetingAttrName;
    }

    @Override
    public String getPersonToGreet(final Principal p) {
        final String greetingPersonId = (String) p.getAttributes().get(this.greetingAttributeName);
        if (!StringUtils.isBlank(greetingPersonId)) {
            return greetingPersonId;
        }
        return p.getId();
    }

}
