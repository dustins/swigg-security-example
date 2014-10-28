/*
 * Copyright
 */

package net.swigg.security.authentication;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class BCryptCredentialsMatcher implements CredentialsMatcher {
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        UsernamePasswordToken authToken = UsernamePasswordToken.class.cast(token);
        return passwordEncoder.matches(new String(authToken.getPassword()), info.getCredentials().toString());
    }

    public BCryptPasswordEncoder getPasswordEncoder() {
        return passwordEncoder;
    }

    @Autowired
    public void setPasswordEncoder(BCryptPasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
}
