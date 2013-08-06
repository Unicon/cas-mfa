package net.unicon.cas.mfa.web.view;

import java.util.Collection;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

import net.unicon.cas.mfa.util.MultiFactorUtils;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.SamlAuthenticationMetaDataPopulator;
import org.jasig.cas.authentication.principal.RememberMeCredentials;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.web.view.AbstractSaml10ResponseView;
import org.joda.time.DateTime;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.Attribute;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.AttributeValue;
import org.opensaml.saml1.core.Audience;
import org.opensaml.saml1.core.AudienceRestrictionCondition;
import org.opensaml.saml1.core.AuthenticationStatement;
import org.opensaml.saml1.core.Conditions;
import org.opensaml.saml1.core.ConfirmationMethod;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml1.core.SubjectConfirmation;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;


/**
 * The successful SAML-based view, closing matching the original implementation
 * at {@link org.jasig.cas.web.view.Saml10SuccessResponseView}. This extension
 * is able to stuff the set of fulfilled authentication methods into the final
 * SAML assertion as attributes.
 * @author Misagh Moayyed
 * @see #putFulfilledAuthenticationMethodsIntoTheModel(AttributeStatement, Set)
 */
public final class Saml10SuccessResponseView extends AbstractSaml10ResponseView {

    /** Namespace for custom attributes. */
    private static final String NAMESPACE = "http://www.ja-sig.org/products/cas/";

    private static final String REMEMBER_ME_ATTRIBUTE_NAME = "longTermAuthenticationRequestTokenUsed";

    private static final String REMEMBER_ME_ATTRIBUTE_VALUE = "true";

    private static final String CONFIRMATION_METHOD = "urn:oasis:names:tc:SAML:1.0:cm:artifact";

    /** Constant representing the authentication method in the model. */
    private static final String MODEL_AUTHN_METHOD = MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD;

    private final XSStringBuilder attrValueBuilder = new XSStringBuilder();

    /** The issuer, generally the host name. */
    @NotNull
    private String issuer;

    /** The amount of time in milliseconds this is valid for. */
    @Min(1000)
    private long issueLength = 30000;

    @NotNull
    private String rememberMeAttributeName = REMEMBER_ME_ATTRIBUTE_NAME;

    @Override
    protected void prepareResponse(final Response response, final Map<String, Object> model) {
        final Authentication authentication = getAssertionFrom(model).getChainedAuthentications().get(0);
        final DateTime issuedAt = response.getIssueInstant();
        final Service service = getAssertionFrom(model).getService();
        final boolean isRemembered = (
                authentication.getAttributes().get(RememberMeCredentials.AUTHENTICATION_ATTRIBUTE_REMEMBER_ME) == Boolean.TRUE
                        && !getAssertionFrom(model).isFromNewLogin());

        // Build up the SAML assertion containing AuthenticationStatement and AttributeStatement
        final Assertion assertion = newSamlObject(Assertion.class);
        assertion.setID(generateId());
        assertion.setIssueInstant(issuedAt);
        assertion.setIssuer(this.issuer);
        assertion.setConditions(newConditions(issuedAt, service.getId()));
        final AuthenticationStatement authnStatement = newAuthenticationStatement(authentication);
        assertion.getAuthenticationStatements().add(authnStatement);
        final Map<String, Object> attributes = authentication.getPrincipal().getAttributes();

        final Set<String> previouslyAchievedAuthenticationMethods =
                MultiFactorUtils.getSatisfiedAuthenticationMethods(authentication);
        if (!attributes.isEmpty() || isRemembered || !previouslyAchievedAuthenticationMethods.isEmpty()) {
            final Subject subject = newSubject(authentication.getPrincipal().getId());
            final AttributeStatement attrStatement =
                    newAttributeStatement(subject, attributes, isRemembered, previouslyAchievedAuthenticationMethods);
            assertion.getAttributeStatements().add(attrStatement);
        }
        response.setStatus(newStatus(StatusCode.SUCCESS, null));
        response.getAssertions().add(assertion);
    }

    private Conditions newConditions(final DateTime issuedAt, final String serviceId) {
        final Conditions conditions = newSamlObject(Conditions.class);
        conditions.setNotBefore(issuedAt);
        conditions.setNotOnOrAfter(issuedAt.plus(this.issueLength));
        final AudienceRestrictionCondition audienceRestriction = newSamlObject(AudienceRestrictionCondition.class);
        final Audience audience = newSamlObject(Audience.class);
        audience.setUri(serviceId);
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictionConditions().add(audienceRestriction);
        return conditions;
    }

    private Subject newSubject(final String identifier) {
        final SubjectConfirmation confirmation = newSamlObject(SubjectConfirmation.class);
        final ConfirmationMethod method = newSamlObject(ConfirmationMethod.class);
        method.setConfirmationMethod(CONFIRMATION_METHOD);
        confirmation.getConfirmationMethods().add(method);
        final NameIdentifier nameIdentifier = newSamlObject(NameIdentifier.class);
        nameIdentifier.setNameIdentifier(identifier);
        final Subject subject = newSamlObject(Subject.class);
        subject.setNameIdentifier(nameIdentifier);
        subject.setSubjectConfirmation(confirmation);
        return subject;
    }

    private AuthenticationStatement newAuthenticationStatement(final Authentication authentication) {
        final String authenticationMethod = (String) authentication.getAttributes().get(
                SamlAuthenticationMetaDataPopulator.ATTRIBUTE_AUTHENTICATION_METHOD);
        final AuthenticationStatement authnStatement = newSamlObject(AuthenticationStatement.class);
        authnStatement.setAuthenticationInstant(new DateTime(authentication.getAuthenticatedDate()));
        authnStatement.setAuthenticationMethod(
                authenticationMethod != null
                        ? authenticationMethod
                        : SamlAuthenticationMetaDataPopulator.AUTHN_METHOD_UNSPECIFIED);
        authnStatement.setSubject(newSubject(authentication.getPrincipal().getId()));
        return authnStatement;
    }

    private AttributeStatement newAttributeStatement(
            final Subject subject, final Map<String, Object> attributes,
            final boolean isRemembered, final Set<String> previouslyAchievedAuthenticationMethods) {

        final AttributeStatement attrStatement = newSamlObject(AttributeStatement.class);
        attrStatement.setSubject(subject);
        for (final Entry<String, Object> e : attributes.entrySet()) {
            if (e.getValue() instanceof Collection<?> && ((Collection<?>) e.getValue()).isEmpty()) {
                log.info("Skipping attribute {} because it does not have any values.", e.getKey());
                continue;
            }
            final Attribute attribute = newSamlObject(Attribute.class);
            attribute.setAttributeName(e.getKey());
            attribute.setAttributeNamespace(NAMESPACE);
            if (e.getValue() instanceof Collection<?>) {
                final Collection<?> c = (Collection<?>) e.getValue();
                for (final Object value : c) {
                    attribute.getAttributeValues().add(newAttributeValue(value));
                }
            } else {
                attribute.getAttributeValues().add(newAttributeValue(e.getValue()));
            }
            attrStatement.getAttributes().add(attribute);
        }

        if (isRemembered) {
            final Attribute attribute = newSamlObject(Attribute.class);
            attribute.setAttributeName(this.rememberMeAttributeName);
            attribute.setAttributeNamespace(NAMESPACE);
            attribute.getAttributeValues().add(newAttributeValue(REMEMBER_ME_ATTRIBUTE_VALUE));
            attrStatement.getAttributes().add(attribute);
        }

        putFulfilledAuthenticationMethodsIntoTheModel(attrStatement, previouslyAchievedAuthenticationMethods);
        return attrStatement;
    }

    private XSString newAttributeValue(final Object value) {
        final XSString stringValue = this.attrValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        if (value instanceof String) {
            stringValue.setValue((String) value);
        } else {
            stringValue.setValue(value.toString());
        }
        return stringValue;
    }

    private void putFulfilledAuthenticationMethodsIntoTheModel(final AttributeStatement attrStatement,
            final Set<String> previouslyAchievedAuthenticationMethods) {
        if (previouslyAchievedAuthenticationMethods.size() > 0) {
            final StringBuilder bldr = new StringBuilder();
            for (final String method : previouslyAchievedAuthenticationMethods) {
                bldr.append(method);
                bldr.append(" ");
            }
            final String authnMethods = bldr.toString().trim();
            if (!StringUtils.isBlank(authnMethods)) {
                final Attribute attribute = newSamlObject(Attribute.class);
                attribute.setAttributeName(MODEL_AUTHN_METHOD);
                attribute.setAttributeNamespace(NAMESPACE);
                attribute.getAttributeValues().add(newAttributeValue(authnMethods));
                attrStatement.getAttributes().add(attribute);
            }
        }
    }

    public void setIssueLength(final long issueLength) {
        this.issueLength = issueLength;
    }

    public void setIssuer(final String issuer) {
        this.issuer = issuer;
    }

    public void setRememberMeAttributeName(final String rememberMeAttributeName) {
        this.rememberMeAttributeName = rememberMeAttributeName;
    }
}
