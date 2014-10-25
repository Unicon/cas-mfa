package com.toopher.integrations.cas.web.flow;
import org.jasig.cas.authentication.principal.Principal;
import com.toopher.integrations.cas.authentication.LevelOfAssurance;

public interface PrincipalLoaResolver {
    LevelOfAssurance getLoa(Principal principal);
}
