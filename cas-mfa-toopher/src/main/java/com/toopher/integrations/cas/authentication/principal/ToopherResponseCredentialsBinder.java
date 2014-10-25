package com.toopher.integrations.cas.authentication.principal;

import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;
import java.util.Enumeration;
import org.apache.log4j.Logger;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.web.bind.CredentialsBinder;
import javax.servlet.http.HttpServletRequest;

public class ToopherResponseCredentialsBinder implements CredentialsBinder {
    private static Logger logger = Logger.getLogger("com.toopher.integrations.cas");

    private static final String KEY_LOGIN_TICKET = "lt";
    private static final String KEY_EXECUTION = "execution";
    private static final String KEY_EVENT_ID = "_eventId";
    private static final String KEY_SERVICE = "service";
    private final static Set<String> KEYS_TO_EXCLUDE = new HashSet<String>(
            Arrays.asList(
                KEY_LOGIN_TICKET,
                KEY_EXECUTION,
                KEY_EVENT_ID,
                KEY_SERVICE));

    @Override
    public void bind(HttpServletRequest request, Credentials credentials) {
        Map<String, String> parameters = new HashMap<String, String>();

        ToopherCredentials toopherCredentials = (ToopherCredentials)credentials;

        Enumeration<String> paramNames = request.getParameterNames();
        for(;paramNames.hasMoreElements();) {
            String paramName = paramNames.nextElement();
            String paramValue = request.getParameter(paramName);

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
    public boolean supports(Class<?> clazz) {
        return (clazz == ToopherCredentials.class);
    }
}
