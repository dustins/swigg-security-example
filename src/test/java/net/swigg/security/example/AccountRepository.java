/*
 * Copyright
 */

package net.swigg.security.example;

import com.google.common.collect.Maps;

import java.util.Map;

/**
 * Dummy account repository
 *
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class AccountRepository {
    private Map<String, Account> accounts = Maps.newHashMap();

    public Account get(String name) {
        return this.accounts.get(name);
    }

    public void addAccount(Account account) {
        this.accounts.put(account.getName(), account);
    }

    public void addAccount(Account... accounts) {
        for (Account account : accounts) {
            this.addAccount(account);
        }
    }

    public void clear() {
        this.accounts.clear();
    }
}
