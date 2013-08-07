package net.unicon.cas.mfa.web.flow.view;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MultifactorLoginViewPrincipalAttributeGreeterTests {

    @Test
    public void testValidPrincipalAttributeToGreet() {
        final Map map = new HashMap();
        map.put("firstName", "cas");
        map.put("lastName", "user");

        final Principal p = new SimplePrincipal("userid", map);

        final MultifactorLoginViewPrincipalAttributeGreeter greeter = new MultifactorLoginViewPrincipalAttributeGreeter(
                "firstName");
        assertEquals(greeter.getPersonToGreet(p), "cas");
    }

    @Test
    public void testInvalidPrincipalAttributeToGreet() {
        final Map map = new HashMap();
        final Principal p = new SimplePrincipal("userid", map);

        final MultifactorLoginViewPrincipalAttributeGreeter greeter = new MultifactorLoginViewPrincipalAttributeGreeter(
                "firstName");
        assertEquals(greeter.getPersonToGreet(p), p.getId());
    }
}
