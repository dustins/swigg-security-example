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

package net.swigg.security.authorization;

import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.authz.permission.PermissionResolver;
import org.apache.shiro.authz.permission.PermissionResolverAware;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Abstract {@link org.apache.shiro.realm.Realm} that implements {@link Authorizer}.
 *
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public abstract class AuthorizingRealm extends AuthenticatingRealm implements Authorizer, PermissionResolverAware {
    private PermissionResolver permissionResolver;

    private PermissionFetcher permissionFetcher;

    public AuthorizingRealm(CredentialsMatcher matcher, PermissionFetcher permissionFetcher) {
        super(matcher);
        this.permissionFetcher = permissionFetcher;
    }

    public AuthorizingRealm(PermissionFetcher permissionFetcher) {
        this.permissionFetcher = permissionFetcher;
    }

    @Override
    public boolean isPermitted(PrincipalCollection principals, String permission) {
        return this.isPermitted(principals, permissionResolver().resolvePermission(permission));
    }

    @Override
    public boolean isPermitted(PrincipalCollection subjectPrincipal, Permission permission) {
        Collection<PrincipalIdentity> identities = subjectPrincipal.byType(PrincipalIdentity.class);
        for (Permission p : permissionFetcher().fetchPermissions(identities, permission)) {
            if (p.implies(permission)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean[] isPermitted(PrincipalCollection subjectPrincipal, String... permissions) {
        List<Permission> perms = new ArrayList<Permission>(permissions.length);
        for (String permString : permissions) {
            perms.add(permissionResolver().resolvePermission(permString));
        }

        return isPermitted(subjectPrincipal, perms);
    }

    @Override
    public boolean[] isPermitted(PrincipalCollection subjectPrincipal, List<Permission> permissions) {
        if (permissions != null) {
            boolean[] result = new boolean[permissions.size()];
            int index = 0;

            for (Permission permission : permissions) {
                result[index] = isPermitted(subjectPrincipal, permission);
                index++;
            }

            return result;
        }

        return new boolean[0];
    }

    @Override
    public boolean isPermittedAll(PrincipalCollection subjectPrincipal, String... permissions) {
        List<Permission> perms = new ArrayList<Permission>(permissions.length);
        for (String permString : permissions) {
            perms.add(permissionResolver().resolvePermission(permString));
        }

        return isPermittedAll(subjectPrincipal, perms);
    }

    @Override
    public boolean isPermittedAll(PrincipalCollection subjectPrincipal, Collection<Permission> permissions) {
        if (permissions != null) {
            for (Permission permission : permissions) {
                if (!isPermitted(subjectPrincipal, permission)) {
                    return false;
                }
            }
        }

        return true;
    }

    @Override
    public void checkPermission(PrincipalCollection subjectPrincipal, String permission) throws AuthorizationException {
        checkPermission(subjectPrincipal, permissionResolver().resolvePermission(permission));
    }

    @Override
    public void checkPermission(PrincipalCollection subjectPrincipal, Permission permission) throws AuthorizationException {
        if (!isPermitted(subjectPrincipal, permission)) {
            String msg = "User is not permitted [" + permission + "]";
            throw new UnauthorizedException(msg);
        }
    }

    @Override
    public void checkPermissions(PrincipalCollection subjectPrincipal, String... permissions) throws AuthorizationException {
        if (permissions != null) {
            for (String permission : permissions) {
                checkPermission(subjectPrincipal, permission);
            }
        }
    }

    @Override
    public void checkPermissions(PrincipalCollection subjectPrincipal, Collection<Permission> permissions) throws AuthorizationException {
        if (permissions != null) {
            for (Permission permission : permissions) {
                checkPermission(subjectPrincipal, permission);
            }
        }
    }

    @Override
    public boolean hasRole(PrincipalCollection subjectPrincipal, String roleIdentifier) {
        if (roleIdentifier != null) {
            for (PrincipalIdentity principalIdentity : subjectPrincipal.byType(PrincipalIdentity.class)) {
                if (principalIdentity.getPrincipalIdentity().equals(roleIdentifier)) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public boolean[] hasRoles(PrincipalCollection subjectPrincipal, List<String> roleIdentifiers) {
        if (roleIdentifiers != null) {
            boolean[] result = new boolean[roleIdentifiers.size()];
            int index = 0;

            for (String roleIdentifier : roleIdentifiers) {
                result[index] = hasRole(subjectPrincipal, roleIdentifier);
                index++;
            }

            return result;
        }

        return new boolean[0];
    }

    @Override
    public boolean hasAllRoles(PrincipalCollection subjectPrincipal, Collection<String> roleIdentifiers) {
        if (roleIdentifiers != null) {
            for (String roleIdentifier : roleIdentifiers) {
                if (!hasRole(subjectPrincipal, roleIdentifier)) {
                    return false;
                }
            }
        }

        return true;
    }

    @Override
    public void checkRole(PrincipalCollection subjectPrincipal, String roleIdentifier) throws AuthorizationException {
        if (!hasRole(subjectPrincipal, roleIdentifier)) {
            String msg = "User does not have role [" + roleIdentifier + "]";
            throw new UnauthorizedException(msg);
        }
    }

    @Override
    public void checkRoles(PrincipalCollection subjectPrincipal, Collection<String> roleIdentifiers) throws AuthorizationException {
        if (roleIdentifiers != null) {
            for (String roleIdentifier : roleIdentifiers) {
                checkRole(subjectPrincipal, roleIdentifier);
            }
        }
    }

    @Override
    public void checkRoles(PrincipalCollection subjectPrincipal, String... roleIdentifiers) throws AuthorizationException {
        for (String roleIdentifier : roleIdentifiers) {
            checkRole(subjectPrincipal, roleIdentifier);
        }
    }

    PermissionResolver permissionResolver() {
        if (this.permissionResolver == null) {
            this.permissionResolver = new WildcardPermissionResolver();
        }

        return permissionResolver;
    }

    @Override
    public void setPermissionResolver(PermissionResolver permissionResolver) {
        this.permissionResolver = permissionResolver;
    }

    public PermissionFetcher permissionFetcher() {
        return permissionFetcher;
    }
}
