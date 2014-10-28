/*
 * Copyright
 */

package net.swigg.security.authorization;

import org.apache.shiro.authz.Permission;

import java.util.Collection;
import java.util.Set;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public interface PermissionFetcher {
    Set<? extends Permission> fetchPermissions(Collection<String> securityIdentities, Permission... permissions);
}
