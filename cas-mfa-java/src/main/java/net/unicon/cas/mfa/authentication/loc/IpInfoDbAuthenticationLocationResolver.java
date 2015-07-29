package net.unicon.cas.mfa.authentication.loc;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.IOUtils;
import org.jasig.cas.web.support.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.RequestContext;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Map;

/**
 * @author Misagh Moayyed
 */
public final class IpInfoDbAuthenticationLocationResolver implements AuthenticationLocationResolver {
    private static final Logger LOGGER = LoggerFactory.getLogger(IpInfoDbAuthenticationLocationResolver.class);

    private final String apiKey;

    /**
     * Instantiates a new Ip info db authentication location resolver.
     *
     * @param apiKey the api key
     */
    public IpInfoDbAuthenticationLocationResolver(final String apiKey) {
        this.apiKey = apiKey;
    }

    @Override
    public AuthenticationLocation resolve(final RequestContext context) {
        try {
            final String json = getLocationViaJson(context);
            final ObjectMapper mapper =  new ObjectMapper();
            final Map<String, String> map = mapper.readValue(json, Map.class);

            final AuthenticationLocationBuilder builder = new AuthenticationLocationBuilder();
            return builder.setCityName(map.get("cityName"))
                   .setIpAddress(map.get("ipAddress"))
                   .setCountryCode(map.get("countryCode"))
                   .setCountryName(map.get("countryName"))
                   .setRegionName(map.get("regionName"))
                   .setLatitude(map.get("latitude"))
                   .setLongitude(map.get("longitude"))
                   .setTimeZone(map.get("timeZone"))
                   .build();
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }

    /**
     * Gets location via json.
     *
     * @param context the context
     * @return the location via json
     * @throws IOException the iO exception
     */
    private String getLocationViaJson(final RequestContext context) throws IOException {
        final HttpServletRequest request = WebUtils.getHttpServletRequest(context);
        final String url = String.format("https://api.ipinfodb.com/v3/ip-city/?key=%s&format=json&ip=%s",
                this.apiKey, request.getRemoteAddr());

        final URL obj = new URL(url);
        HttpsURLConnection con = null;
        BufferedReader in = null;
        try {
            con = (HttpsURLConnection) obj.openConnection();
            con.setRequestMethod("GET");
            con.setRequestProperty("User-Agent",
                    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36");

            final int responseCode = con.getResponseCode();

            in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            final StringBuilder response = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            return response.toString();
        } finally {
            IOUtils.closeQuietly(in);
        }
    }
}
