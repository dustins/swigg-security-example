/*
 * Copyright
 */

package net.swigg.security.authorization;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public interface SecurityIdentity {
    String getSecurityIdentityBase();

    String getSecurityIdentity();
}
