package com.toopher.integrations.cas.authentication.principal;

/**
 * Created by drew on 2/27/14.
 */
public interface UsernameToEmailMapper {
    String getEmailForUsername(String username);
}
