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

import com.google.common.collect.Sets;
import net.swigg.security.authorization.AuthorizingRealm;
import net.swigg.security.authorization.PermissionFetcher;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;

import java.util.Set;

/**
 * Implementation of {@link AuthorizingRealm} that provides authentication using {@link Account}s
 *
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class ExampleRealm extends AuthorizingRealm {
    private AccountRepository accountRepository;

    public ExampleRealm(CredentialsMatcher matcher, PermissionFetcher permissionFetcher, AccountRepository accountRepository) {
        super(matcher, permissionFetcher);
        this.accountRepository = accountRepository;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = UsernamePasswordToken.class.cast(token);
        String principal = upToken.getUsername();
        Account account = this.accountRepository.get(principal);

        // no account matches that principal
        if (null == account) {
            throw new UnknownAccountException();
        }

        Set<Object> principals = Sets.newHashSet(account.getName(), account);
        principals.addAll(account.getRoles());
        PrincipalCollection principalCollection = new SimplePrincipalCollection(principals, getName());

        return new SimpleAuthenticationInfo(principalCollection, account.getPassword());
    }
}
