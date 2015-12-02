package net.unicon.cas.mfa;

import com.github.inspektr.audit.annotation.Audit;
import net.unicon.cas.mfa.authentication.principal.MultiFactorCredentials;
import net.unicon.cas.mfa.util.MultiFactorUtils;
import net.unicon.cas.mfa.web.support.MultiFactorAuthenticationSupportingWebApplicationService;
import org.apache.commons.lang.StringUtils;
import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationManager;
import org.jasig.cas.authentication.MutableAuthentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.PersistentIdGenerator;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.authentication.principal.ShibbolethCompatiblePersistentIdGenerator;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;
import org.jasig.cas.services.UnauthorizedServiceException;
import org.jasig.cas.ticket.ExpirationPolicy;
import org.jasig.cas.ticket.InvalidTicketException;
import org.jasig.cas.ticket.ServiceTicket;
import org.jasig.cas.ticket.TicketException;
import org.jasig.cas.ticket.TicketGrantingTicket;
import org.jasig.cas.ticket.TicketGrantingTicketImpl;
import org.jasig.cas.ticket.TicketValidationException;
import org.jasig.cas.ticket.registry.TicketRegistry;
import org.jasig.cas.util.UniqueTicketIdGenerator;
import org.jasig.cas.validation.Assertion;
import org.jasig.cas.validation.ImmutableAssertionImpl;
import org.perf4j.aop.Profiled;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;

import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * An extension of {@link CentralAuthenticationService} that routes CAS requests to a delegate,
 * thereby allowing the ability to partially override behavior that is MFA specific.
 * The current implementation is specific on the operation of creating ticket creating tickets
 * based on the assumptions that the credentials received are of type {@link MultiFactorCredentials}
 * and that the authentication context is verified and readily available, based on which the TGT will
 * be added to the configured {@link TicketRegistry}.
 *
 * This implementation here is merely responsible for creating the ticket granting ticket
 * and again, assumes that the authentication context has been established by all other
 * authentication managers in the flow. The authentication context is carried within the
 * {@link MultiFactorCredentials} instance.
 *
 * Assumptions: the TicketRegistry wired into this CentralAuthenticationService instance is the same as that wired
 * into the wrapped delegate.
 * (That way when this implementation adds tickets directly to the registry in createTGT and delegateTGT
 * those tickets will be available to the delegate in its fulfilling such methods as grantServiceTicket.)
 *
 *
 * @author Misagh Moayyed
 */
public final class MultiFactorAwareCentralAuthenticationService implements CentralAuthenticationService {

    /** Log instance for logging events, info, warnings, errors, etc. */
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    /** The wrapped CentralAuthenticationService. */
    private CentralAuthenticationService delegate;

    private UniqueTicketIdGenerator ticketGrantingTicketUniqueTicketIdGenerator;

    private TicketRegistry ticketRegistry;

    private ExpirationPolicy ticketGrantingTicketExpirationPolicy;

    private AuthenticationManager authenticationManager;

    /** New Ticket Registry for storing and retrieving services tickets. Can point to the same one as the ticketRegistry variable. */
    @NotNull
    private TicketRegistry serviceTicketRegistry;

    /** Encoder to generate PseudoIds. */
    @NotNull
    private PersistentIdGenerator persistentIdGenerator = new ShibbolethCompatiblePersistentIdGenerator();

    /** The authentication method attribute name to include in the response. **/
    @NotNull
    private String authenticationMethodAttributeName = MultiFactorAuthenticationSupportingWebApplicationService.CONST_PARAM_AUTHN_METHOD;

    /** Implementation of Service Manager. */
    @NotNull
    private ServicesManager servicesManager;


    @Override
    @Audit(
            action="TICKET_GRANTING_TICKET",
            actionResolverName="CREATE_TICKET_GRANTING_TICKET_RESOLVER",
            resourceResolverName="CREATE_TICKET_GRANTING_TICKET_RESOURCE_RESOLVER")
    @Profiled(tag = "CREATE_TICKET_GRANTING_TICKET", logFailuresSeparately = false)
    public String createTicketGrantingTicket(final Credentials credentials) throws TicketException {
        final MultiFactorCredentials mfaCredentials = (MultiFactorCredentials) credentials;
        final Authentication authentication = mfaCredentials.getAuthentication();

        final TicketGrantingTicket ticketGrantingTicket = new TicketGrantingTicketImpl(
                this.ticketGrantingTicketUniqueTicketIdGenerator.getNewTicketId(TicketGrantingTicket.PREFIX), authentication,
                this.ticketGrantingTicketExpirationPolicy);

        this.ticketRegistry.addTicket(ticketGrantingTicket);
        return ticketGrantingTicket.getId();
    }

    /*
     * Implements Audit Trail participation by virtue of the delegate's audit trail participation.
     */
    @Override
    public String grantServiceTicket(final String ticketGrantingTicketId, final Service service) throws TicketException {
        return this.delegate.grantServiceTicket(ticketGrantingTicketId, service);
    }

    /*
     * Implements Audit Trail participation by virtue of the delegate's audit trail participation.
     */
    @Override
    public String grantServiceTicket(final String ticketGrantingTicketId, final Service service, final Credentials credentials)
            throws TicketException {
        return this.delegate.grantServiceTicket(ticketGrantingTicketId, service, credentials);
    }

    /*
     * Implements Audit Trail participation by virtue of the delegate's audit trail participation.
     */
    @Override
    @Audit(
            action="SERVICE_TICKET_VALIDATE",
            actionResolverName="VALIDATE_SERVICE_TICKET_RESOLVER",
            resourceResolverName="VALIDATE_SERVICE_TICKET_RESOURCE_RESOLVER")
    @Profiled(tag="VALIDATE_SERVICE_TICKET", logFailuresSeparately = false)
    public Assertion validateServiceTicket(final String serviceTicketId, final Service service) throws TicketException {
        Assert.notNull(serviceTicketId, "serviceTicketId cannot be null");
        Assert.notNull(service, "service cannot be null");

        final ServiceTicket serviceTicket = (ServiceTicket) this.serviceTicketRegistry.getTicket(serviceTicketId, ServiceTicket.class);

        final RegisteredService registeredService = this.servicesManager.findServiceBy(service);

        if (registeredService == null || !registeredService.isEnabled()) {
            logger.warn("ServiceManagement: Service {} does not exist or is not enabled in registry.", service);
            throw new UnauthorizedServiceException("Service not allowed to validate tickets.");
        }

        if (serviceTicket == null) {
            logger.info("ServiceTicket [" + serviceTicketId + "] does not exist.");
            throw new InvalidTicketException();
        }

        try {
            synchronized (serviceTicket) {
                if (serviceTicket.isExpired()) {
                    logger.info("ServiceTicket [" + serviceTicketId + "] has expired.");
                    throw new InvalidTicketException();
                }

                if (!serviceTicket.isValidFor(service)) {
                    logger.error("ServiceTicket {} with service {}  does not match supplied service {}",
                            serviceTicketId, serviceTicket.getService().getId(), service);
                    throw new TicketValidationException(serviceTicket.getService());
                }
            }

            final List<Authentication> chainedAuthenticationsList = serviceTicket.getGrantingTicket().getChainedAuthentications();
            final Authentication authentication = chainedAuthenticationsList.get(chainedAuthenticationsList.size() - 1);
            final Principal principal = authentication.getPrincipal();

            final String principalId = determinePrincipalIdForRegisteredService(principal, registeredService, serviceTicket);
            final Authentication authToUse;

            if (!registeredService.isIgnoreAttributes()) {
                final Map<String, Object> attributes = new HashMap<String, Object>();

                for (final String attribute : registeredService.getAllowedAttributes()) {
                    final Object value = principal.getAttributes().get(attribute);

                    if (value != null) {
                        attributes.put(attribute, value);
                    }
                }
                final String authnMethod = MultiFactorUtils.getFulfilledAuthenticationMethodsAsString(authentication);
                if (StringUtils.isNotBlank(authnMethod)) {
                    attributes.put(this.authenticationMethodAttributeName, authnMethod);
                }

                final Principal modifiedPrincipal = new SimplePrincipal(principalId, attributes);
                final MutableAuthentication mutableAuthentication = new MutableAuthentication(
                        modifiedPrincipal, authentication.getAuthenticatedDate());
                mutableAuthentication.getAttributes().putAll(
                        authentication.getAttributes());
                mutableAuthentication.getAuthenticatedDate().setTime(
                        authentication.getAuthenticatedDate().getTime());
                authToUse = mutableAuthentication;
            } else {

                final Map<String, Object> attributes = new HashMap<String, Object>(principal.getAttributes());
                final String authnMethod = MultiFactorUtils.getFulfilledAuthenticationMethodsAsString(authentication);
                if (StringUtils.isNotBlank(authnMethod)) {
                    attributes.put(this.authenticationMethodAttributeName, authnMethod);
                }

                final Principal modifiedPrincipal = new SimplePrincipal(principalId, attributes);
                authToUse = new MutableAuthentication(modifiedPrincipal, authentication.getAuthenticatedDate());
            }

            final List<Authentication> authentications = new ArrayList<Authentication>();

            for (int i = 0; i < chainedAuthenticationsList.size() - 1; i++) {
                authentications.add(serviceTicket.getGrantingTicket().getChainedAuthentications().get(i));
            }
            authentications.add(authToUse);

            return new ImmutableAssertionImpl(authentications, serviceTicket.getService(), serviceTicket.isFromNewLogin());
        } finally {
            if (serviceTicket.isExpired()) {
                this.serviceTicketRegistry.deleteTicket(serviceTicketId);
            }
        }
    }

    /*
     * Implements Audit Trail participation by virtue of the delegate's audit trail participation.
     */
    @Override
    public void destroyTicketGrantingTicket(final String ticketGrantingTicketId) {
        this.delegate.destroyTicketGrantingTicket(ticketGrantingTicketId);
    }

    @Override
    @Audit(
            action="PROXY_GRANTING_TICKET",
            actionResolverName="GRANT_PROXY_GRANTING_TICKET_RESOLVER",
            resourceResolverName="GRANT_PROXY_GRANTING_TICKET_RESOURCE_RESOLVER")
    @Profiled(tag="GRANT_PROXY_GRANTING_TICKET", logFailuresSeparately = false)
    public String delegateTicketGrantingTicket(final String serviceTicketId, final Credentials credentials) throws TicketException {
        return this.delegate.delegateTicketGrantingTicket(serviceTicketId, credentials);
    }

    /**
     * Determines the principal id to use for a {@link RegisteredService} using the following rules:
     *
     * <ul>
     *  <li> If the service is marked to allow anonymous access, a persistent id is returned. </li>
     *  <li> If the attribute name is undefined, then the default principal id is returned.</li>
     *  <li>If the service is set to ignore attributes, or the username attribute exists in the allowed attributes for the service,
     *      the corresponding attribute value will be returned.
     *  </li>
     *   <li>Otherwise, the default principal's id is returned as the username attribute with an additional warning.</li>
     * </ul>
     *
     * @param principal The principal object to be validated and constructed
     * @param registeredService Requesting service for which a principal is being validated.
     * @param serviceTicket An instance of the service ticket used for validation
     *
     * @return The principal id to use for the requesting registered service
     */
    private String determinePrincipalIdForRegisteredService(final Principal principal, final RegisteredService registeredService,
                                                            final ServiceTicket serviceTicket) {
        String principalId = null;
        final String serviceUsernameAttribute = registeredService.getUsernameAttribute();

        if (registeredService.isAnonymousAccess()) {
            principalId = this.persistentIdGenerator.generate(principal, serviceTicket.getService());
        } else if (StringUtils.isBlank(serviceUsernameAttribute)) {
            principalId = principal.getId();
        } else {
            if ((registeredService.isIgnoreAttributes() || registeredService.getAllowedAttributes().contains(serviceUsernameAttribute))
                    && principal.getAttributes().containsKey(serviceUsernameAttribute)) {
                principalId = principal.getAttributes().get(registeredService.getUsernameAttribute()).toString();
            } else {
                principalId = principal.getId();
                final Object[] errorLogParameters = new Object[] {principalId, registeredService.getUsernameAttribute(),
                        principal.getAttributes(), registeredService.getServiceId(), principalId };
                logger.warn("Principal [{}] did not have attribute [{}] among attributes [{}] so CAS cannot "
                        + "provide on the validation response the user attribute the registered service [{}] expects. "
                        + "CAS will instead return the default username attribute [{}]", errorLogParameters);
            }

        }

        logger.debug("Principal id to return for service [{}] is [{}]. The default principal id is [{}].",
                registeredService.getName(), principal.getId(), principalId);
        return principalId;
    }

    public void setAuthenticationManager(final AuthenticationManager manager) {
        this.authenticationManager = manager;
    }

    /**
     * The set TicketRegistry should be the same registry used by the CentralAuthenticationService instance
     * provided to setCentralAuthenticationServiceDelegate.
     * @param ticketRegistry non-null TicketRegistry shared with the delegate CAS
     */
    /**
     * Method to set the TicketRegistry.
     *
     * @param ticketRegistry the TicketRegistry to set.
     */
    public void setTicketRegistry(final TicketRegistry ticketRegistry) {
        this.ticketRegistry = ticketRegistry;

        if (this.serviceTicketRegistry == null) {
            this.serviceTicketRegistry = ticketRegistry;
        }
    }

    public void setServiceTicketRegistry(final TicketRegistry serviceTicketRegistry) {
        this.serviceTicketRegistry = serviceTicketRegistry;
    }

    /**
     * Inject a ticket granting ticket expiration policy.
     * @param ticketGrantingTicketExpirationPolicy the non-null policy on TGT expiration.
     */
    public void setTicketGrantingTicketExpirationPolicy(final ExpirationPolicy ticketGrantingTicketExpirationPolicy) {
        this.ticketGrantingTicketExpirationPolicy = ticketGrantingTicketExpirationPolicy;
    }

    public void setServicesManager(final ServicesManager servicesManager) {
        this.servicesManager = servicesManager;
    }

    /**
     * Inject a TGT unique ID generator.
     * @param uniqueTicketIdGenerator the non-null TGT unique ID generator.
     */
    public void setTicketGrantingTicketUniqueTicketIdGenerator(final UniqueTicketIdGenerator uniqueTicketIdGenerator) {
        this.ticketGrantingTicketUniqueTicketIdGenerator = uniqueTicketIdGenerator;
    }

    /**
     * Inject a delegate CAS implementation to fulfill the non-TGT-creating CAS API methods.
     * The delegate CAS instance should share a TicketRegistry with this CAS instance otherwise this CAS will be
     * granting TGTs that will not be honored by the delegate.
     * @param cas the non-null delegate CAS
     */
    public void setCentralAuthenticationServiceDelegate(final CentralAuthenticationService cas) {
        this.delegate = cas;
    }

    /**
     * Sets authentication method attribute name.
     *
     * @param authenticationMethodAttributeName the authentication method attribute name
     */
    public void setAuthenticationMethodAttributeName(final String authenticationMethodAttributeName) {
        this.authenticationMethodAttributeName = authenticationMethodAttributeName;
    }

    public void setPersistentIdGenerator(final PersistentIdGenerator persistentIdGenerator) {
        this.persistentIdGenerator = persistentIdGenerator;
    }
}
