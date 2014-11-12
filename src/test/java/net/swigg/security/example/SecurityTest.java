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
import net.swigg.security.authentication.AuthenticationConfig;
import net.swigg.security.authentication.BCryptCredentialsMatcher;
import net.swigg.security.authorization.AuthorizationConfig;
import net.swigg.security.authorization.PrincipalWildcardPermission;
import net.swigg.security.authorization.PermissionFetcher;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.Subject;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.Collection;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static net.swigg.security.authorization.TargetIdentity.ANY;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
@ContextConfiguration(classes = {SecurityTest.Config.class})
@RunWith(SpringJUnit4ClassRunner.class)
public class SecurityTest {
    @Autowired
    AccountRepository accountRepository;

    @PersistenceContext
    EntityManager entityManager;

    @After
    public void tearDown() throws Exception {
        accountRepository.clear();
    }

    @Test
    @Transactional
    public void testPermissions() throws Exception {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        Role adminRole = new Role("admin");
        Role memberRole = new Role("member");
        Role guestRole = new Role("guest");

        // add basic accounts
        Account kermit = new Account(1, "kermit", passwordEncoder.encode("kermit1"), adminRole, memberRole);
        Account fozzy = new Account(2, "fozzy", passwordEncoder.encode("fozzy1"), memberRole);
        accountRepository.addAccount(kermit, fozzy);

        // setup test permissions
        entityManager.persist(new PrincipalWildcardPermission(adminRole, "*:*:*"));            // admin role can do anything
        entityManager.persist(new PrincipalWildcardPermission(memberRole, "account:read:*"));  // members can read any account
        entityManager.persist(new PrincipalWildcardPermission(guestRole, "account:create"));  // guests can create an account
        entityManager.persist(new PrincipalWildcardPermission(fozzy, "account:delete").setTargets(fozzy));   // fozzy can delete his own account

        // login as kermit
        SecurityUtils.getSubject().login(new UsernamePasswordToken("kermit", "kermit1"));
        Subject subject = SecurityUtils.getSubject();

        // what roles does kermit have?
        assertTrue(subject.hasRole(adminRole.getPrincipalIdentity()));
        assertTrue(subject.hasRole(memberRole.getPrincipalIdentity()));
        assertFalse(subject.hasRole(guestRole.getPrincipalIdentity()));

        // can kermit generally do anything?
        assertTrue(subject.isPermitted(new AccountPermission().create()));
        assertTrue(subject.isPermitted(new AccountPermission().read()));
        assertTrue(subject.isPermitted(new AccountPermission().delete()));
        assertTrue(subject.isPermitted(new AccountPermission(ANY).create()));
        assertTrue(subject.isPermitted(new AccountPermission(ANY).read()));
        assertTrue(subject.isPermitted(new AccountPermission(ANY).delete()));

        // can kermit do stuff to his own account?
        assertTrue(subject.isPermitted(new AccountPermission(kermit).create())); // this is meaningless, but kermit can do anything
        assertTrue(subject.isPermitted(new AccountPermission(kermit).read()));
        assertTrue(subject.isPermitted(new AccountPermission(kermit).delete()));

        // can kermit do stuff to fozzy's account?
        assertTrue(subject.isPermitted(new AccountPermission(fozzy).create())); // this is meaningless, but kermit can do anything
        assertTrue(subject.isPermitted(new AccountPermission(fozzy).read()));
        assertTrue(subject.isPermitted(new AccountPermission(fozzy).delete()));

        // login as fozzy
        SecurityUtils.getSubject().login(new UsernamePasswordToken("fozzy", "fozzy1"));
        subject = SecurityUtils.getSubject();

        // what roles does fozzy have?
        assertFalse(subject.hasRole(adminRole.getPrincipalIdentity()));
        assertTrue(subject.hasRole(memberRole.getPrincipalIdentity()));
        assertFalse(subject.hasRole(guestRole.getPrincipalIdentity()));

        // can fozzy generally do anything?
        assertFalse(subject.isPermitted(new AccountPermission().create()));            // no permission implies "account:create"
        assertTrue(subject.isPermitted(new AccountPermission().read()));               // member implies "account:read:*"
        assertFalse(subject.isPermitted(new AccountPermission().delete()));            // no permission implies "account:delete"
        assertFalse(subject.isPermitted(new AccountPermission(ANY).create()));  // no permission implies: "account:create:*"
        assertTrue(subject.isPermitted(new AccountPermission(ANY).read()));     // member implies "account:read:*"
        assertFalse(subject.isPermitted(new AccountPermission(ANY).delete()));  // no permission implies "account:delete:*"

        // can fozzy do stuff to his own account?
        assertFalse(subject.isPermitted(new AccountPermission(fozzy).create()));  // this is meaningless, but technically no permissions implies "account:create:account-2"
        assertTrue(subject.isPermitted(new AccountPermission(fozzy).read()));     // member implies "account:read:*"
        assertTrue(subject.isPermitted(new AccountPermission(fozzy).delete()));   // as fozzy: "account:delete:account-2"

        // can fozzy do stuff to kermit's account?
        assertFalse(subject.isPermitted(new AccountPermission(kermit).create())); // no permission implies "account:create:account-1"
        assertTrue(subject.isPermitted(new AccountPermission(kermit).read()));    // member implies "account:read:*"
        assertFalse(subject.isPermitted(new AccountPermission(kermit).delete())); // no permission implies "account:delete:account-1"
    }

    @Configuration
    @EnableAutoConfiguration(exclude = {SecurityAutoConfiguration.class})
    @Import({AuthorizationConfig.class, AuthenticationConfig.class})
    public static class Config {
        @Bean
        public ExampleRealm securityTestAuthorizingRealm(BCryptCredentialsMatcher credentialsMatcher, PermissionFetcher permissionFetcher, AccountRepository accountRepository) {
            return new ExampleRealm(credentialsMatcher, permissionFetcher, accountRepository);
        }

        @Bean
        public org.apache.shiro.mgt.SecurityManager securityManager(Collection<Realm> realms) {
            org.apache.shiro.mgt.SecurityManager securityManager = new DefaultSecurityManager(realms);
            SecurityUtils.setSecurityManager(securityManager);

            return securityManager;
        }

        @Bean
        public AccountRepository accountRepository() {
            return new AccountRepository();
        }
    }
}
