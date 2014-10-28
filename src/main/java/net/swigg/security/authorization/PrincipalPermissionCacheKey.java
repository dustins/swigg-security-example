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

import com.google.common.base.Objects;
import com.google.common.collect.Sets;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.Set;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class PrincipalPermissionCacheKey {
    private PrincipalCollection principalCollection;

    private Set<Permission> permissions;

    public PrincipalPermissionCacheKey(PrincipalCollection principalCollection, Permission[] permissions) {
        this.principalCollection = principalCollection;
        this.permissions = Sets.newHashSet(permissions);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(principalCollection, permissions);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final PrincipalPermissionCacheKey other = (PrincipalPermissionCacheKey) obj;
        return Objects.equal(this.principalCollection, other.principalCollection) && Objects.equal(this.permissions, other.permissions);
    }
}
