package net.unicon.cas.mfa.authentication.duo;

import org.jasig.cas.authentication.principal.AbstractPersonDirectoryCredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;

import javax.annotation.PostConstruct;
import java.util.List;

/**
 * Initialize the application context with the needed webflow mfa configuration
 * as much as possible to simplify adding mfa into an existing overlay.
 *
 * @author Misagh Moayyed
 */
@Component
public class DuoMultiFactorWebflowConfigurer implements InitializingBean {
    private static final Logger LOGGER = LoggerFactory.getLogger(DuoMultiFactorWebflowConfigurer.class);

    @Autowired
    private WebApplicationContext context;


    @PostConstruct
    @Override
    public void afterPropertiesSet() throws Exception {
        try {
            final List resolvers = this.context.getBean("mfaCredentialsToPrincipalResolvers", List.class);
            resolvers.add(0, new DuoCredentialsToPrincipalResolver());
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    private class DuoCredentialsToPrincipalResolver extends AbstractPersonDirectoryCredentialsToPrincipalResolver {

        @Override
        protected String extractPrincipalId(final Credentials credentials) {
            final DuoCredentials duoCredentials = (DuoCredentials) credentials;
            return duoCredentials.getUsername();
        }

        @Override
        public boolean supports(final Credentials credentials) {
            return credentials != null && credentials instanceof DuoCredentials;
        }
    }
}
