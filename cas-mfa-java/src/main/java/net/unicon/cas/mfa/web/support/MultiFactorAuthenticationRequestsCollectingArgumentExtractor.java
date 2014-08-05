package net.unicon.cas.mfa.web.support;

import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationRequestContext;
import net.unicon.cas.mfa.authentication.MultiFactorAuthenticationTransactionContext;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.web.support.ArgumentExtractor;
import org.springframework.webflow.execution.RequestContextHolder;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.Set;

/**
 * Composite argument extractor that collects and aggregates all possible mfa requests
 * (from different sources e.g. request param, registered service attribute), encapsulates them in
 * {@link net.unicon.cas.mfa.authentication.MultiFactorAuthenticationTransactionContext} and binds it to the SWF's conversation scope
 * under the {@code MultiFactorAuthenticationTransactionContext.class#getSimpleName} key.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon inc.
 */
public final class MultiFactorAuthenticationRequestsCollectingArgumentExtractor implements ArgumentExtractor {


    /**
     * A set of delegate mfa argument extractors.
     */
    private final Set<AbstractMultiFactorAuthenticationArgumentExtractor> mfaArgumentExstractors;

    /**
     * A config map with ranking numbers per mfa method type.
     */
    private final Map<String, Integer> mfaRankingConfig;

    /**
     * Ctor.
     *
     * @param mfaArgumentExstractors delegate argument extractors
     * @param mfaRankingConfig the mfa ranking config
     */
    public MultiFactorAuthenticationRequestsCollectingArgumentExtractor(
            final Set<AbstractMultiFactorAuthenticationArgumentExtractor> mfaArgumentExstractors,
            final Map<String, Integer> mfaRankingConfig) {

        this.mfaArgumentExstractors = mfaArgumentExstractors;
        this.mfaRankingConfig = mfaRankingConfig;
    }

    @Override
    public WebApplicationService extractService(final HttpServletRequest request) {
        MultiFactorAuthenticationTransactionContext mfaTxCtx = null;

        for (AbstractMultiFactorAuthenticationArgumentExtractor extractor : this.mfaArgumentExstractors) {
            final MultiFactorAuthenticationSupportingWebApplicationService service =
                    MultiFactorAuthenticationSupportingWebApplicationService.class.cast(extractor.extractService(request));

            if (service != null) {
                final int mfaMethodRank = this.mfaRankingConfig.get(service.getAuthenticationMethod());
                if (mfaTxCtx != null) {
                    mfaTxCtx.addMfaRequest(createMfaRequest(service, mfaMethodRank));
                } else {
                    mfaTxCtx = new MultiFactorAuthenticationTransactionContext(
                            service.getId()).addMfaRequest(createMfaRequest(service, mfaMethodRank));
                }
            }
        }

        if (mfaTxCtx != null) {
            //This is not unit testable (well in Java anyway, but would be possible if this class was written in Groovy),
            // but it's the only way to reach into the SWF context from here,
            //and since there is no desire to use httpservletrequest attribute to get this object out.
            RequestContextHolder.getRequestContext().getConversationScope()
                    .put(MultiFactorAuthenticationTransactionContext.class.getSimpleName(), mfaTxCtx);
        }
        //Always return null as we have collected all the mfa requests
        return null;
    }

    /**
     * Helper to create mfa requests.
     *
     * @param service mfa service
     * @param mfaMethodRank mfa source rank value
     *
     * @return mfa request
     */
    private MultiFactorAuthenticationRequestContext createMfaRequest(final MultiFactorAuthenticationSupportingWebApplicationService service,
                                                                     final int mfaMethodRank) {
        return new MultiFactorAuthenticationRequestContext(service, mfaMethodRank);
    }
}
