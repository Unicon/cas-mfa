package net.unicon.cas.mfa.authentication.handler;

import org.jasig.cas.authentication.principal.Principal;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Misagh Moayyed
 */
public class InMemoryAuthyUserAccountStore implements AuthyUserAccountStore {

    private Map<Principal, Long> accountsMap = new ConcurrentHashMap<Principal, Long>();

    @Override
    public void add(final Long authyId, final Principal principal) {
        this.accountsMap.put(principal, authyId);
    }

    @Override
    public boolean contains(final Principal principal) {
        return get(principal) != null;
    }

    @Override
    public Long get(final Principal principal) {
        return this.accountsMap.get(principal);
    }
}
