/*
 * Copyright
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
