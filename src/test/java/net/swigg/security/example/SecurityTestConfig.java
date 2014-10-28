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

import net.swigg.security.authentication.AuthenticationConfig;
import net.swigg.security.authentication.BCryptCredentialsMatcher;
import net.swigg.security.authorization.AuthorizationConfig;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
@Configuration
@EnableAutoConfiguration(exclude = {SecurityAutoConfiguration.class})
@Import({AuthorizationConfig.class, AuthenticationConfig.class})
public class SecurityTestConfig {
    @Bean
    public SecurityTestAuthorizingRealm securityTestAuthorizingRealm(BCryptCredentialsMatcher credentialsMatcher) {
        SecurityTestAuthorizingRealm realm = new SecurityTestAuthorizingRealm();
        realm.setCredentialsMatcher(credentialsMatcher);

        return realm;
    }

    @Bean
    public org.apache.shiro.mgt.SecurityManager securityManager(SecurityTestAuthorizingRealm authorizingRealm) {
        SecurityManager securityManager = new DefaultSecurityManager(authorizingRealm);
        SecurityUtils.setSecurityManager(securityManager);

        return securityManager;
    }

    @Bean
    public AccountRepository accountRepository() {
        return new AccountRepository();
    }
}
