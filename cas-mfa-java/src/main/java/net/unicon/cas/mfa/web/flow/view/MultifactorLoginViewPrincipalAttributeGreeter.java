package net.unicon.cas.mfa.web.flow.view;

import org.apache.commons.lang3.StringUtils;
import org.jasig.cas.authentication.principal.Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.binding.message.Message;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageContext;
import org.springframework.binding.message.MessageResolver;

import java.util.Collection;

/**
 * Greets the principal by a configurable principal attribute and falls back
 * to the principal id, if none is found.
 * @author Misagh Moayyed
 */
public final class MultifactorLoginViewPrincipalAttributeGreeter implements MultiFactorLoginViewPrincipalGreeter {

    private static final Logger LOGGER = LoggerFactory.getLogger(MultifactorLoginViewPrincipalAttributeGreeter.class);

    /**
     * MessageSource code.
     */
    public static final String CODE = "screen.mfa.welcome.back";

    private final String greetingAttributeName;

    /**
     * @param greetingAttrName attribute name
     */
    public MultifactorLoginViewPrincipalAttributeGreeter(final String greetingAttrName) {
        this.greetingAttributeName = greetingAttrName;
    }

    @Override
    public String getPersonToGreet(final Principal p, final MessageContext messageContext) {

        String personId = p.getId();
        final Object attrValue = p.getAttributes().get(this.greetingAttributeName);

        if (attrValue == null) {
            LOGGER.warn("No attribute value could be found for [{}]", this.greetingAttributeName);
            return p.getId();
        }

        String greetingPersonId = attrValue.toString();
        if (attrValue instanceof Collection) {
            final Collection col =((Collection) attrValue);
            if (!col.isEmpty()) {
                greetingPersonId = col.iterator().next().toString();
                LOGGER.warn("Found multiple attribute values [{}] for [{}] to greet. Picked [{}]",
                        attrValue, this.greetingAttributeName,
                        greetingPersonId);
            }
        }

        if (!StringUtils.isBlank(greetingPersonId)) {
            personId = greetingPersonId;
        }

        final MessageResolver resolver = new MessageBuilder().source(CODE).info().code(CODE).arg(personId).build();
        messageContext.addMessage(resolver);

        final Message[] messages = messageContext.getMessagesBySource(CODE);
        if (messages == null || messages.length == 0) {
            LOGGER.warn("The greeting message for principal [{}] could not be resolved by the "
                    + "code [{}] in any of the configured message resource bundles. Falling back to principal id [{}]",
                    p, CODE, p.getId());
            return p.getId();
        }
        return messages[0].getText();
    }

}
