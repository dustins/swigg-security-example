/*
 * Copyright
 */

package net.swigg.security.authentication;

import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class AuthenticationConfig {
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CredentialsMatcher bCryptCredentialsMatcher() {
        return new BCryptCredentialsMatcher();
    }
}
