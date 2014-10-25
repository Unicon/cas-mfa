package com.toopher.integrations.cas.authentication.principal;

import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.web.bind.CredentialsBinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ToopherResponseCredentialsBinder implements CredentialsBinder {
    private Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final String KEY_LOGIN_TICKET = "lt";
    private static final String KEY_EXECUTION = "execution";
    private static final String KEY_EVENT_ID = "_eventId";
    private static final String KEY_SERVICE = "service";

    private static final Set<String> KEYS_TO_EXCLUDE = new HashSet<String>(
            Arrays.asList(
                KEY_LOGIN_TICKET,
                KEY_EXECUTION,
                KEY_EVENT_ID,
                KEY_SERVICE));

    @Override
    public void bind(final  HttpServletRequest request, final  Credentials credentials) {
        final Map<String, String> parameters = new HashMap<String, String>();

        ToopherCredentials toopherCredentials = (ToopherCredentials) credentials;

        final Enumeration<String> paramNames = request.getParameterNames();
        for(;paramNames.hasMoreElements();) {
            final String paramName = paramNames.nextElement();
            final String paramValue = request.getParameter(paramName);

            if (!KEYS_TO_EXCLUDE.contains(paramName)) {
                logger.debug("adding paramName = " + paramName + " = " + paramValue);
                parameters.put(paramName, paramValue);
            }

            if (paramName.equals(KEY_LOGIN_TICKET)) {
                toopherCredentials.setLoginTicketId(paramValue);
            }
        }

        toopherCredentials.setRequestParameters(parameters);
    }

    @Override
    public boolean supports(final Class<?> clazz) {
        return (clazz == ToopherCredentials.class);
    }
}
