package net.unicon.cas.addons.serviceregistry;

import org.jasig.cas.services.RegisteredService;

import java.util.Map;

/**
 * An extension to <code>RegisteredService</code> with extra arbitrary attributes.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon, inc.
 */
public interface RegisteredServiceWithAttributes extends RegisteredService {

    /**
     * Gets extra attributes.
     *
     * @return the extra attributes
     */
    Map<String, Object> getExtraAttributes();

}
