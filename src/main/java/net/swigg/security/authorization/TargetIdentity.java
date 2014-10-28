/*
 * Copyright
 */

package net.swigg.security.authorization;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public interface TargetIdentity {
    String getTargetIdentityBase();

    String getTargetIdentity();
}
