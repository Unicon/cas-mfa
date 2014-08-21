package net.unicon.cas.mfa.authentication;

import org.jasig.cas.authentication.AuthenticationManager;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;

/**
 * Initialize the application context with the needed mfa configuratio
 * as much as possible to simplify adding mfa into an existing overlay.
 * @author Misagh Moayyed
 */
public final class CasMultiFactorApplicationContextAware implements InitializingBean {
    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    @Qualifier("authenticationManager")
    private AuthenticationManager authenticationManager;

    @Override
    public void afterPropertiesSet() throws Exception {
        final Field f = authenticationManager.getClass().getDeclaredField("authenticationMetaDataPopulators");
        final Object list = f.getType().newInstance();
        final Method add = List.class.getDeclaredMethod("add", Object.class);
        add.invoke(list, new RememberAuthenticationMethodMetaDataPopulator());
    }
}
