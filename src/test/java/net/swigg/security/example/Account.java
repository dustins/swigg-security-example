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
import net.swigg.security.authorization.PrincipalIdentity;
import net.swigg.security.authorization.TargetIdentity;

import java.util.Set;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class Account implements PrincipalIdentity, TargetIdentity {
    private Integer id;

    private String name;

    private String password;

    private Set<Role> roles;

    public Account(Integer id, String name, String password, Role... roles) {
        this.id = id;
        this.name = name;
        this.password = password;
        this.roles = Sets.newHashSet(roles);
    }

    public Integer getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = Sets.newHashSet(roles);
    }

    @Override
    public String getPrincipalIdentity() {
        return "account:" + getId();
    }

    @Override
    public String getTargetIdentity() {
        return "account-" + getId();
    }
}
