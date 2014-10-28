/*
 * Copyright
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
