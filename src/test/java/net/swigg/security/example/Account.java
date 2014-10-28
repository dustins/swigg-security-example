/*
 * Copyright
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
