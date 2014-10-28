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

import com.google.common.collect.Sets;
import net.swigg.security.authorization.SecurityIdentity;
import net.swigg.security.authorization.TargetIdentity;

import java.util.Set;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class Account implements SecurityIdentity, TargetIdentity {
    private String name;

    private char[] password;

    private Set<Role> roles;

    public Account(String name, char[] password, Role... roles) {
        this.name = name;
        this.password = password;
        this.roles = Sets.newHashSet(roles);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public char[] getPassword() {
        return password;
    }

    public void setPassword(char[] password) {
        this.password = password;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = Sets.newHashSet(roles);
    }

    @Override
    public String getSecurityIdentityBase() {
        return "account:";
    }

    @Override
    public String getSecurityIdentity() {
        return getSecurityIdentityBase() + getName();
    }

    @Override
    public String getTargetIdentityBase() {
        return "account-";
    }

    @Override
    public String getTargetIdentity() {
        return getTargetIdentityBase() + getName();
    }
}
