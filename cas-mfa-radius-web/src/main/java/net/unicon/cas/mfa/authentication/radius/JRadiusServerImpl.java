package net.unicon.cas.mfa.authentication.radius;

import net.jradius.client.RadiusClient;
import net.jradius.client.auth.RadiusAuthenticator;
import net.jradius.dictionary.Attr_NASIPAddress;
import net.jradius.dictionary.Attr_NASIdentifier;
import net.jradius.dictionary.Attr_NASPort;
import net.jradius.dictionary.Attr_NASPortType;
import net.jradius.dictionary.Attr_UserName;
import net.jradius.dictionary.Attr_UserPassword;
import net.jradius.dictionary.AttributeDictionaryImpl;
import net.jradius.exception.RadiusException;
import net.jradius.exception.UnknownAttributeException;
import net.jradius.packet.AccessAccept;
import net.jradius.packet.AccessRequest;
import net.jradius.packet.RadiusPacket;
import net.jradius.packet.attribute.AttributeFactory;
import net.jradius.packet.attribute.AttributeList;
import net.unicon.cas.mfa.web.flow.util.MultiFactorRequestContextUtils;
import org.apache.commons.lang.StringUtils;
import org.jasig.cas.adaptors.radius.RadiusServer;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.execution.RequestContextHolder;

import java.net.InetAddress;
import java.net.UnknownHostException;


/**
 * Implementation of a RadiusServer that utilizes the JRadius packages available
 * at <a href="http://jradius.sf.net">http://jradius.sf.net</a>. This impl
 * differs from the default provided by CAS since it allows to provide NAS
 * details.
 */
public final class JRadiusServerImpl implements RadiusServer {

    private static final Logger LOGGER = LoggerFactory.getLogger(JRadiusServerImpl.class);

    /**
     * The port to do accounting on.
     */
    protected final int accountingPort;

    /**
     * The port to do authentication on.
     */
    protected final int authenticationPort;

    /**
     * The timeout for sockets.
     */
    protected final int socketTimeout;

    /**
     * The conversion from hostname to an InetAddress.
     */
    protected final InetAddress inetAddress;

    /**
     * The shared secret to send to the RADIUS server.
     */
    protected final String sharedSecret;

    /**
     * The number of retries to do per authentication request.
     */
    protected final int retries;

    /** The radius Authenticator to use. */
    protected final RadiusAuthenticator radiusAuthenticator;

    /** The Nas ip address. */
    protected final String nasIpAddress;

    /** Nas port. */
    protected final long nasPort;

    /** Should nas settings be enabled? */
    protected boolean enableNas = false;

    /** Nas id... */
    protected final long nasIdentifier;

    /** Nas port type... */
    protected final Long nasPortType;

    /** is radius server case sensitive? */
    protected boolean caseSensitive = true;

    /** Load the dictionary implementation. */
    static {
        AttributeFactory.loadAttributeDictionary(AttributeDictionaryImpl.class.getCanonicalName());
    }

    /**
     * Instantiates a new jradius server impl.
     *
     * @param hostName            the host name
     * @param sharedSecret        the shared secret
     * @param radiusAuthenticator the radius authenticator
     * @param authenticationPort  the authentication port
     * @param accountingPort      the accounting port
     * @param socketTimeout       the socket timeout
     * @param retries             the retries
     * @param nasIpAddress        the nas ip address
     * @param nasPort             the nas port
     * @param nasIdentifier       the nas identifier
     * @param nasPortType         the nas port type
     * @throws UnknownHostException the unknown host exception
     */
    public JRadiusServerImpl(final String hostName, final String sharedSecret,
                             final RadiusAuthenticator radiusAuthenticator,
                             final int authenticationPort, final int accountingPort,
                             final int socketTimeout, final int retries,
                             final String nasIpAddress, final long nasPort,
                             final long nasIdentifier, final Long nasPortType) throws UnknownHostException {
        this.sharedSecret = sharedSecret;
        this.authenticationPort = authenticationPort;
        this.accountingPort = accountingPort;
        this.socketTimeout = socketTimeout;
        this.retries = retries;
        this.radiusAuthenticator = radiusAuthenticator;
        this.inetAddress = InetAddress.getByName(hostName);
        this.nasIpAddress = nasIpAddress;
        this.nasPort = nasPort;
        this.nasIdentifier = nasIdentifier;
        this.nasPortType = nasPortType;
    }

    @Override
    public boolean authenticate(final UsernamePasswordCredentials usernamePasswordCredentials) {

        final UsernamePasswordCredentials otpC = prepareRadiusOneTimeCredentials(usernamePasswordCredentials);
        final AttributeList attributeList = prepareRadiusAttributeList(otpC);

        try {

            final RadiusClient radiusClient = getNewRadiusClient();
            final AccessRequest request = new AccessRequest(radiusClient, attributeList);

            final RadiusPacket response = radiusClient.authenticate(request,
                    this.radiusAuthenticator, this.retries);

            // accepted
            if (response instanceof AccessAccept) {
                LOGGER.debug("Authentication request succeeded for host: [{}] and username [{}]",
                        this.inetAddress.getCanonicalHostName(), usernamePasswordCredentials.getUsername());
                return true;
            }

            // rejected
            LOGGER.debug("Authentication request failed for host: [{}] and username [{}]",
                    this.inetAddress.getCanonicalHostName(), usernamePasswordCredentials.getUsername());
            return false;
        } catch (final UnknownAttributeException e) {
            throw new IllegalArgumentException("Passed an unknown attribute to radius client", e);
        } catch (final RadiusException e) {
            throw new IllegalStateException("Received response that puts radius client into illegal state", e);
        }
    }

    /**
     * Prepare radius attribute list.
     *
     * @param usernamePasswordCredentials the username password credentials
     * @return the attribute list
     */
    protected AttributeList prepareRadiusAttributeList(final UsernamePasswordCredentials usernamePasswordCredentials) {
        final AttributeList attributeList = new AttributeList();
        attributeList.add(new Attr_UserName(usernamePasswordCredentials.getUsername()));
        attributeList.add(new Attr_UserPassword(usernamePasswordCredentials.getPassword()));

        if (this.enableNas) {
            if (StringUtils.isNotBlank(this.nasIpAddress)) {
                LOGGER.debug("Adding NAS ip address [{}] to the radius attribute list", this.nasIpAddress);
                attributeList.add(new Attr_NASIPAddress(new String(this.nasIpAddress)));
            } else {
                try {
                    final String hostIpAddress = InetAddress.getLocalHost().getHostAddress();
                    LOGGER.debug("Adding auto-configured NAS ip address [{}] the radius attribute list", hostIpAddress);
                } catch (final Exception e) {
                    throw new RuntimeException(e.getMessage(), e);
                }
            }

            if (this.nasPort > 0) {
                LOGGER.debug("Adding NAS port [{}] to the radius attribute list", this.nasPort);
                attributeList.add(new Attr_NASPort(new Long(this.nasPort)));
            }

            if (this.nasIdentifier > 0) {
                LOGGER.debug("Adding NAS Identifier [{}] to the radius attribute list", this.nasIdentifier);
                attributeList.add(new Attr_NASIdentifier(new Long(this.nasIdentifier)));
            }

            if (this.nasPortType != null) {
                LOGGER.debug("Adding NAS port type [{}] to the radius attribute list", this.nasPortType);
                attributeList.add(new Attr_NASPortType(this.nasPortType));
            }

        } else {
            LOGGER.debug("NAS is not enabled. Skipping over settings...");
        }
        return attributeList;
    }

    /**
     * Prepare radius one time credentials.
     *
     * @param usernamePasswordCredentials the username password credentials
     * @return the username password credentials
     */
    protected UsernamePasswordCredentials prepareRadiusOneTimeCredentials(final UsernamePasswordCredentials usernamePasswordCredentials) {
        final RequestContext context = RequestContextHolder.getRequestContext();

        String pin = usernamePasswordCredentials.getUsername();
        if (this.caseSensitive) {
            pin = pin.toLowerCase();
            LOGGER.debug("Treating pin as case sensitive. Converted to [{}]", pin);
        }

        final String otp = pin.concat(usernamePasswordCredentials.getPassword());
        LOGGER.debug("Concatenated pin and password upon radius authentication for [{}]", pin);

        final UsernamePasswordCredentials newCreds = new UsernamePasswordCredentials();

        LOGGER.debug("Attempting to locate user id for radius authentication...");
        final Principal principalId = MultiFactorRequestContextUtils.getMultiFactorPrimaryPrincipal(context);

        if (this.caseSensitive) {
            newCreds.setUsername(principalId.getId().toLowerCase());
            LOGGER.debug("Treating user id as case sensitive. Converted to [{}]", principalId);
        } else {
            newCreds.setUsername(principalId.getId());
        }
        newCreds.setPassword(otp);

        LOGGER.trace("Using [{}]:[{}] as credentials for radius authentication...",
                newCreds.getUsername(), newCreds.getPassword());

        return newCreds;
    }

    protected RadiusClient getNewRadiusClient() {
        return new RadiusClient(this.inetAddress, this.sharedSecret,
                this.authenticationPort, this.accountingPort, this.socketTimeout);
    }



    public void setEnableNas(final boolean enableNas) {
        this.enableNas = enableNas;
    }

    public void setCaseSensitive(final boolean caseSensitive) {
        this.caseSensitive = caseSensitive;
    }
}

