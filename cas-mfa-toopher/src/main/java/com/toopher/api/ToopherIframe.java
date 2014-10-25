package com.toopher.api;

import oauth.signpost.OAuthConsumer;
import oauth.signpost.basic.DefaultOAuthConsumer;
import oauth.signpost.exception.OAuthException;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

public final class ToopherIframe {
    private static final String IFRAME_VERSION = "2";
    private static Logger logger = LoggerFactory.getLogger(ToopherIframe.class);

    public static final String pairIframeUrl(String userName, String resetEmail, long ttl, String baseUrl, String key, String secret) {
        final List<NameValuePair> params = new ArrayList<NameValuePair>(4);
        params.add(new BasicNameValuePair("v", IFRAME_VERSION));
        params.add(new BasicNameValuePair("username", userName));
        params.add(new BasicNameValuePair("reset_email", resetEmail));
        params.add(new BasicNameValuePair("expires", String.valueOf((new Date().getTime() / 1000) + ttl)));
        return getOAuthUrl(baseUrl + "web/pair", params, key, secret);
    }

    public static final String authIframeUrl(String userName, String resetEmail, String actionName,
                                             boolean automationAllowed, boolean challengeRequired,
                                             String sessionToken, String requesterMetadata, long ttl,
                                             String baseUrl, String key, String secret) {
        final List<NameValuePair> params = new ArrayList<NameValuePair>(9);
        params.add(new BasicNameValuePair("v", IFRAME_VERSION));
        params.add(new BasicNameValuePair("username", userName));
        params.add(new BasicNameValuePair("action_name", actionName));
        params.add(new BasicNameValuePair("automation_allowed", automationAllowed ? "True" : "False"));
        params.add(new BasicNameValuePair("challenge_required", challengeRequired ? "True" : "False"));
        params.add(new BasicNameValuePair("reset_email", resetEmail));
        params.add(new BasicNameValuePair("session_token", sessionToken));
        params.add(new BasicNameValuePair("requester_metadata", requesterMetadata));
        params.add(new BasicNameValuePair("expires", String.valueOf((new Date().getTime() / 1000) + ttl)));
        return getOAuthUrl(baseUrl + "web/auth", params, key, secret);
    }

    public static final Map<String, String> validate(String secret, Map<String, String> data, long ttl) {
        try {
            logger.debug("ToopherIframe.validate()");
            List<String> missingKeys = new ArrayList<String>();
            if (!data.containsKey("toopher_sig")) {
                missingKeys.add("toopher_sig");
            }
            if (!data.containsKey("timestamp")) {
                missingKeys.add("timestamp");
            }
            if (missingKeys.size() > 0) {
                for (String missingKey : missingKeys) {
                    logger.debug("Missing required key: " + missingKey);
                }
                return null;
            }

            String maybeSig = data.get("toopher_sig");
            data.remove("toopher_sig");
            boolean signatureValid;
            try {
                String computedSig = signature(secret, data);
                signatureValid = computedSig.equals(maybeSig);
                logger.debug("submitted = " + maybeSig);
                logger.debug("computed  = " + computedSig);
            } catch (Exception e) {
                logger.debug("error while calculating signature", e);
                signatureValid = false;
            }

            boolean ttlValid = (new Date().getTime() / 1000) - ttl < Long.parseLong(data.get("timestamp"));
            logger.debug("ttlValid is " + ttlValid);
            if (signatureValid && ttlValid) {
                return data;
            } else {
                return null;
            }
        } catch (Exception e) {
            logger.debug("Exception while validating toopher signature", e);
            return null;
        }
    }

    private static String signature(String secret, Map<String, String> data) throws NoSuchAlgorithmException, InvalidKeyException {
        TreeSet<String> sortedKeys = new TreeSet<String>(data.keySet());
        List<NameValuePair> sortedParams = new ArrayList<NameValuePair>(data.size());
        for (String key : sortedKeys) {
            sortedParams.add(new BasicNameValuePair(key, data.get(key)));
        }
        String toSign = URLEncodedUtils.format(sortedParams, "UTF-8");
        logger.debug("signing string: " + toSign);
        logger.debug("signing key: " + secret);

        byte[] secretBytes = secret.getBytes();
        SecretKeySpec signingKey = new SecretKeySpec(secretBytes, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signingKey);
        return org.apache.commons.codec.binary.Base64.encodeBase64String(mac.doFinal(toSign.getBytes())).trim();
    }

    private static final String getOAuthUrl(String url, List<NameValuePair> params, String key, String secret) {
        final OAuthConsumer consumer = new DefaultOAuthConsumer(key, secret);
        try {
            return consumer.sign(url + "?" + URLEncodedUtils.format(params, "UTF-8"));
        } catch (OAuthException e) {
            try {
                return url + "web/error.html?message=" + URLEncoder.encode(e.getMessage(), "UTF-8");
            } catch (UnsupportedEncodingException f) {
                return url + "web/error.html?message=Unknown%20Error";
            }
        }
    }
}
