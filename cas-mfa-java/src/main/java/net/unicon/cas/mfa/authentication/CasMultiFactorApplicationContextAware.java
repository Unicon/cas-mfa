package net.unicon.cas.mfa.authentication;

import org.jasig.cas.web.support.ArgumentExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;

import javax.annotation.PostConstruct;
import java.util.List;

/**
 * Initialize the application context with the needed mfa configuration
 * as much as possible to simplify adding mfa into an existing overlay.
 *
 * @author Misagh Moayyed
 */
@Component
public final class CasMultiFactorApplicationContextAware implements InitializingBean {
    private static final Logger LOGGER = LoggerFactory.getLogger(CasMultiFactorApplicationContextAware.class);

    @Autowired
    private FlowBuilderServices flowBuilderServices;

    @Autowired
    @Qualifier("mfaRequestsCollectingArgumentExtractor")
    private ArgumentExtractor mfaRequestsCollectingArgumentExtractor;

    @Override
    @PostConstruct
    public void afterPropertiesSet() throws Exception {
        try {
            LOGGER.debug("Configuring application context for multifactor authentication...");
            addMultifactorArgumentExtractorConfiguration();
            LOGGER.debug("Configured application context for multifactor authentication.");

        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    /**
     * Add multifactor argument extractor configuration.
     */
    private void addMultifactorArgumentExtractorConfiguration() {
        LOGGER.debug("Configuring application context with [{}]",
                mfaRequestsCollectingArgumentExtractor.getClass().getName());

        final List<ArgumentExtractor> list = this.flowBuilderServices.getApplicationContext().getBean("argumentExtractors", List.class);
        list.add(0, mfaRequestsCollectingArgumentExtractor);
    }


}
