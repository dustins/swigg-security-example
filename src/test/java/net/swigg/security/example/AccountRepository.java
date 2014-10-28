/*
 * Copyright. This file is part of swigg-security.
 *
 * swigg-security is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Foobar is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with swigg-security.  If not, see <http://www.gnu.org/licenses/>.
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
