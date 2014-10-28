/*
 * Copyright
 */

package net.swigg.security;

import net.swigg.security.authorization.PermissionFetcher;
import net.swigg.security.authorization.PrincipalPermissionCacheKey;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.PermissionResolver;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
@Component
public abstract class SecurityAuthorizingRealmAbstract extends AuthorizingRealm {
    public static final String PROVIDER_NAME = "net.swigg.musicgame";

    static private final Logger LOGGER = LoggerFactory.getLogger(SecurityAuthorizingRealmAbstract.class);

    private PermissionFetcher permissionFetcher;

    @Override
    public boolean supports(AuthenticationToken token) {
        return UsernamePasswordToken.class.isInstance(token);
    }

    @Override
    public boolean isPermitted(PrincipalCollection principals, Permission permission) {
        AuthorizationInfo info = getAuthorizationInfo(principals, permission);
        return isPermitted(permission, info);
    }

    private boolean isPermitted(Permission permission, AuthorizationInfo info) {
        Collection<Permission> perms = getPermissions(info);
        if (perms != null && !perms.isEmpty()) {
            for (Permission perm : perms) {
                if (perm.implies(permission)) {
                    return true;
                }
            }
        }
        return false;
    }

    private Collection<Permission> getPermissions(AuthorizationInfo info) {
        Set<Permission> permissions = new HashSet<Permission>();

        if (info != null) {
            Collection<Permission> perms = info.getObjectPermissions();
            if (!CollectionUtils.isEmpty(perms)) {
                permissions.addAll(perms);
            }
            perms = resolvePermissions(info.getStringPermissions());
            if (!CollectionUtils.isEmpty(perms)) {
                permissions.addAll(perms);
            }

            perms = resolveRolePermissions(info.getRoles());
            if (!CollectionUtils.isEmpty(perms)) {
                permissions.addAll(perms);
            }
        }

        if (permissions.isEmpty()) {
            return Collections.emptySet();
        } else {
            return Collections.unmodifiableSet(permissions);
        }
    }

    private Collection<Permission> resolvePermissions(Collection<String> stringPerms) {
        Collection<Permission> perms = Collections.emptySet();
        PermissionResolver resolver = getPermissionResolver();
        if (resolver != null && !CollectionUtils.isEmpty(stringPerms)) {
            perms = new LinkedHashSet<Permission>(stringPerms.size());
            for (String strPermission : stringPerms) {
                Permission permission = getPermissionResolver().resolvePermission(strPermission);
                perms.add(permission);
            }
        }
        return perms;
    }

    private Collection<Permission> resolveRolePermissions(Collection<String> roleNames) {
        Collection<Permission> perms = Collections.emptySet();
        RolePermissionResolver resolver = getRolePermissionResolver();
        if (resolver != null && !CollectionUtils.isEmpty(roleNames)) {
            perms = new LinkedHashSet<Permission>(roleNames.size());
            for (String roleName : roleNames) {
                Collection<Permission> resolved = resolver.resolvePermissionsInRole(roleName);
                if (!CollectionUtils.isEmpty(resolved)) {
                    perms.addAll(resolved);
                }
            }
        }
        return perms;
    }

    @Override
    public boolean[] isPermitted(PrincipalCollection principals, List<Permission> permissions) {
        AuthorizationInfo info = getAuthorizationInfo(principals, permissions.toArray(new Permission[permissions.size()]));
        return isPermitted(permissions, info);
    }

    @Override
    public boolean isPermittedAll(PrincipalCollection principal, Collection<Permission> permissions) {
        AuthorizationInfo info = getAuthorizationInfo(principal, permissions.toArray(new Permission[permissions.size()]));
        return info != null && isPermittedAll(permissions, info);
    }

    @Override
    public void checkPermission(PrincipalCollection principal, Permission permission) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo(principal, permission);
        checkPermission(permission, info);
    }

    @Override
    public void checkPermissions(PrincipalCollection principal, Collection<Permission> permissions) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo(principal, permissions.toArray(new Permission[permissions.size()]));
        checkPermissions(permissions, info);
    }

    abstract protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals, Permission... permissions);

    private AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals, Permission... permissions) {
        if (principals == null) {
            return null;
        }

        AuthorizationInfo info = null;

        LOGGER.trace("Retrieving AuthorizationInfo for principals [" + principals + "]");
        Cache<Object, AuthorizationInfo> cache = getAvailableAuthorizationCache();
        if (cache != null) {
            LOGGER.trace("Attempting to retrieve the AuthorizationInfo from cache.");
            Object key = getAuthorizationCacheKey(principals, permissions);
            info = cache.get(key);

            if (info == null) {
                LOGGER.trace("No AuthorizationInfo found in cache for principals [" + principals + "]");
            } else {
                LOGGER.trace("AuthorizationInfo found in cache for principals [" + principals + "]");
            }
        }

        if (info == null) {
            info = doGetAuthorizationInfo(principals, permissions);
            if (info != null && cache != null) {
                LOGGER.trace("Caching authorization info for principals: [" + principals + "].");
                Object key = getAuthorizationCacheKey(principals, permissions);
                cache.put(key, info);
            }
        }

        return info;
    }

    private Object getAuthorizationCacheKey(PrincipalCollection principals, Permission[] permissions) {
        return new PrincipalPermissionCacheKey(principals, permissions);
    }

    private Cache<Object, AuthorizationInfo> getAvailableAuthorizationCache() {
        Cache<Object, AuthorizationInfo> cache = getAuthorizationCache();
        if (cache == null && isAuthorizationCachingEnabled()) {
            cache = getAuthorizationCacheLazy();
        }
        return cache;
    }

    private Cache<Object, AuthorizationInfo> getAuthorizationCacheLazy() {

        if (this.getAuthorizationCache() == null) {

            LOGGER.debug("No authorizationCache instance set.  Checking for a cacheManager...");

            CacheManager cacheManager = getCacheManager();

            if (cacheManager != null) {
                String cacheName = getAuthorizationCacheName();
                LOGGER.debug("CacheManager [" + cacheManager + "] has been configured.  Building " +
                        "authorization cache named [" + cacheName + "]");
                Cache<Object, AuthorizationInfo> authCache = cacheManager.getCache(cacheName);
                this.setAuthorizationCache(authCache);
            } else {
                LOGGER.info("No cache or cacheManager properties have been set.  Authorization cache cannot " +
                        "be obtained.");
            }
        }

        return this.getAuthorizationCache();
    }

    public UsernamePasswordToken wrapToken(AuthenticationToken token) {
        return UsernamePasswordToken.class.cast(token);
    }

    public PermissionFetcher getPermissionFetcher() {
        return permissionFetcher;
    }

    @Autowired
    public void setPermissionFetcher(PermissionFetcher permissionFetcher) {
        this.permissionFetcher = permissionFetcher;
    }

    @Autowired
    @Override
    public void setCredentialsMatcher(CredentialsMatcher credentialsMatcher) {
        super.setCredentialsMatcher(credentialsMatcher);
    }

    @Autowired
    @Override
    public void setRolePermissionResolver(RolePermissionResolver permissionRoleResolver) {
        super.setRolePermissionResolver(permissionRoleResolver);
    }
}
