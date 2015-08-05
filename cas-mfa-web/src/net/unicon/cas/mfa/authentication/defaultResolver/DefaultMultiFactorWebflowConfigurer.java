package net.unicon.cas.mfa.authentication.defaultResolver;

import java.util.List;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;

/**
 * Initialize the application context with the needed webflow mfa configuration
 * as much as possible to simplify adding mfa into an existing overlay.
 *
 * @author Dan Hankins
 */
@Component
public class DefaultMultiFactorWebflowConfigurer implements InitializingBean {
    private static final Logger LOGGER = LoggerFactory.getLogger(DuoMultiFactorWebflowConfigurer.class);

    @Autowired
    private WebApplicationContext context;


    @PostConstruct
    @Override
    public void afterPropertiesSet() throws Exception {
        try {
            final List resolvers = this.context.getBean("mfaCredentialsToPrincipalResolvers", List.class);
            resolvers.add(new UsernamePasswordCredentialsToPrincipalResolver());
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }
}
