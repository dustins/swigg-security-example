/*
 * Copyright
 */

package net.swigg.security.example;

import net.swigg.security.authorization.DomainPermissionEntity;
import net.swigg.security.authorization.SecurityIdentity;
import net.swigg.security.authorization.TargetIdentity;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class AccountPermission extends DomainPermissionEntity {
    public static final String PERMISSION_DOMAIN = "account";

    public AccountPermission() {
        super(PERMISSION_DOMAIN, WILDCARD_TOKEN, WILDCARD_TOKEN);
    }

    public AccountPermission(String actions) {
        super(PERMISSION_DOMAIN, actions);
    }

    public AccountPermission(String actions, String targets) {
        super(PERMISSION_DOMAIN, actions, targets);
    }

    public AccountPermission(String actions, TargetIdentity target) {
        super(PERMISSION_DOMAIN, actions, target.getTargetIdentity());
    }

    public AccountPermission(SecurityIdentity securityIdentity, String actions, String targets) {
        super(securityIdentity, PERMISSION_DOMAIN, actions, targets);
    }

    public AccountPermission(SecurityIdentity securityIdentity, String actions, TargetIdentity target) {
        super(securityIdentity, PERMISSION_DOMAIN, actions, target.getTargetIdentity());
    }

    public static AccountPermission create() {
        return new AccountPermission("create");
    }

    public static AccountPermission create(TargetIdentity target) {
        return new AccountPermission("create", target);
    }

    public static AccountPermission read() {
        return new AccountPermission("read");
    }

    public static AccountPermission read(TargetIdentity target) {
        return new AccountPermission("read", target);
    }

    public static AccountPermission delete() {
        return new AccountPermission("delete");
    }

    public static AccountPermission delete(TargetIdentity target) {
        return new AccountPermission("delete", target);
    }
}