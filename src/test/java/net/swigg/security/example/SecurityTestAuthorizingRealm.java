/*
 * Copyright
 */

package net.swigg.security.example;

import com.google.common.base.Function;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import net.swigg.security.SecurityAuthorizingRealmAbstract;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.Nullable;
import java.util.List;
import java.util.Set;

/**
 * Dummy authenticating/authorizing realm.
 *
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class SecurityTestAuthorizingRealm extends SecurityAuthorizingRealmAbstract {
    private AccountRepository accountRepository;

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String principal = wrapToken(token).getUsername();

        // no account matches that principal
        if (null == principal) {
            throw new UnknownAccountException();
        }

        Account account = this.accountRepository.get(principal);

        Set<Object> principals = Sets.newHashSet(account.getName(), account);
        PrincipalCollection principalCollection = new SimplePrincipalCollection(principals, getName());

        return new SimpleAuthenticationInfo(principalCollection, new String(account.getPassword()));
    }

    /**
     * Simple fetch of AuthorizationInfo for the given principals for roles only. For a full AuthorizationInfo object,
     * {@link #getAuthorizationInfo(org.apache.shiro.subject.PrincipalCollection, org.apache.shiro.authz.Permission...)}
     * should be called.
     *
     * @param principals
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String accountName = principals.oneByType(String.class);
        Account account = this.accountRepository.get(accountName);
        if (null == account) {
            return null;
        }

        Iterable<String> roleNames = Iterables.transform(account.getRoles(), new Function<Role, String>() {
            @Nullable
            @Override
            public String apply(@Nullable Role input) {
                return input.getName();
            }
        });

        return new SimpleAuthorizationInfo(Sets.newHashSet(roleNames));
    }

    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals, Permission... permissions) {
        String accountName = principals.oneByType(String.class);
        Account account = this.accountRepository.get(accountName);
        if (null == account) {
            return null;
        }

        List<String> securityIdentities = Lists.newArrayList();
        Set<String> roleNames = Sets.newHashSet();
        securityIdentities.add(account.getSecurityIdentity());
        for (Role role : account.getRoles()) {
            securityIdentities.add(role.getSecurityIdentity());
        }

        Set<? extends Permission> ownedPermissions = getPermissionFetcher().fetchPermissions(securityIdentities, permissions);
        Set<Permission> objectPermissions = Sets.newHashSet(ownedPermissions);
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roleNames);
        info.setObjectPermissions(objectPermissions);

        return info;
    }

    @Autowired
    public void setAccountRepository(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }
}
