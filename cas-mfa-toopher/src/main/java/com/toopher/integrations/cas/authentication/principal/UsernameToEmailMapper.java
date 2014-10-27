package com.toopher.integrations.cas.authentication.principal;

import org.jasig.cas.authentication.principal.Principal;

public interface UsernameToEmailMapper {
    String getEmailForUsername(Principal principal);
}
