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

import net.swigg.security.authorization.DomainPermissionEntity;
import net.swigg.security.authorization.PrincipalIdentity;
import net.swigg.security.authorization.TargetIdentity;

/**
 * Implementation of {@link org.apache.shiro.authz.Permission} specifically for {@link Account}s.
 *
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

    public AccountPermission(PrincipalIdentity principalIdentity, String actions, String targets) {
        super(principalIdentity, PERMISSION_DOMAIN, actions, targets);
    }

    public AccountPermission(PrincipalIdentity principalIdentity, String actions, TargetIdentity target) {
        super(principalIdentity, PERMISSION_DOMAIN, actions, target.getTargetIdentity());
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
