/*
 * Copyright
 */

package net.swigg.security.example;

import net.swigg.security.authorization.SecurityIdentity;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class Role implements SecurityIdentity {
    private String name;

    public Role(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    @Override
    public String getSecurityIdentityBase() {
        return "role:";
    }

    @Override
    public String getSecurityIdentity() {
        return getSecurityIdentityBase() + getName();
    }
}
