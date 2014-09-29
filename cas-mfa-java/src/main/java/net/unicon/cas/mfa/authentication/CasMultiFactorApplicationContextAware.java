package net.unicon.cas.mfa.authentication;

import org.jasig.cas.authentication.AuthenticationManager;
import org.jasig.cas.web.support.ArgumentExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.List;

/**
 * Initialize the application context with the needed mfa configuratio
 * as much as possible to simplify adding mfa into an existing overlay.
 *
 * @author Misagh Moayyed
 */
@Component
public final class CasMultiFactorApplicationContextAware implements InitializingBean {
    private static final Logger LOGGER = LoggerFactory.getLogger(CasMultiFactorApplicationContextAware.class);

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    @Qualifier("authenticationManager")
    private AuthenticationManager authenticationManager;

    @Autowired
    @Qualifier("mfaRequestsCollectingArgumentExtractor")
    private ArgumentExtractor mfaRequestsCollectingArgumentExtractor;

    @Override
    @PostConstruct
    public void afterPropertiesSet() throws Exception {
        LOGGER.debug("Configuring application context for multifactor authentication...");
        addMultifactorArgumentExtractorConfiguration();
        LOGGER.debug("Configured application context for multifactor authentication.");
    }

    /**
     * Add multifactor argument extractor configuration.
     */
    private void addMultifactorArgumentExtractorConfiguration() {
        LOGGER.debug("Configuring application context with [{}]",
                mfaRequestsCollectingArgumentExtractor.getClass().getName());

        final List<ArgumentExtractor> list = this.applicationContext.getBean("argumentExtractors", List.class);
        list.add(0, mfaRequestsCollectingArgumentExtractor);
    }

}
