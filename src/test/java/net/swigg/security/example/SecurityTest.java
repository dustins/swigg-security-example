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

import net.swigg.security.authorization.DomainPermissionEntity;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Class Description
 *
 * @author Dustin Sweigart <dustin@swigg.net>
 */
@ContextConfiguration(classes = {SecurityTestConfig.class})
@RunWith(SpringJUnit4ClassRunner.class)
public class SecurityTest {
    @Autowired
    AccountRepository accountRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @PersistenceContext
    EntityManager entityManager;

    @After
    public void tearDown() throws Exception {
        accountRepository.clear();
    }

    @Test
    @Transactional
    public void testPermissions() throws Exception {
        Role adminRole = new Role("admin");
        Role memberRole = new Role("member");

        // add basic accounts
        Account kermit = new Account("kermit", passwordEncoder.encode("kermit1").toCharArray(), adminRole, memberRole);
        Account fozzy = new Account("fozzy", passwordEncoder.encode("fozzy1").toCharArray(), memberRole);
        accountRepository.addAccount(kermit, fozzy);

        // setup test permissions
        entityManager.persist(new DomainPermissionEntity(adminRole, "*", "*", "*"));
        entityManager.persist(new DomainPermissionEntity(memberRole, "account", "read", "*"));
        entityManager.persist(new DomainPermissionEntity(memberRole, "account", "create", ""));
        entityManager.persist(new DomainPermissionEntity(fozzy, "account", "delete", fozzy));

        // login as kermit
        SecurityUtils.getSubject().login(new UsernamePasswordToken("kermit", "kermit1"));
        Subject subject = SecurityUtils.getSubject();

        // what roles does kermit have?
        assertTrue(subject.hasRole("admin"));
        assertTrue(subject.hasRole("member"));
        assertFalse(subject.hasRole("god"));

        // can kermit generally do anything?
        assertTrue(subject.isPermitted(AccountPermission.create()));
        assertTrue(subject.isPermitted(AccountPermission.create(DomainPermissionEntity.ANY_TARGET)));
        assertTrue(subject.isPermitted(AccountPermission.read()));
        assertTrue(subject.isPermitted(AccountPermission.read(DomainPermissionEntity.ANY_TARGET)));
        assertTrue(subject.isPermitted(AccountPermission.delete()));
        assertTrue(subject.isPermitted(AccountPermission.delete(DomainPermissionEntity.ANY_TARGET)));

        // can kermit do stuff to his own account?
        assertTrue(subject.isPermitted(AccountPermission.create(kermit))); // this is meaningless, but kermit can do anything
        assertTrue(subject.isPermitted(AccountPermission.read(kermit)));
        assertTrue(subject.isPermitted(AccountPermission.delete(kermit)));

        // can kermit do stuff to fozzy's account?
        assertTrue(subject.isPermitted(AccountPermission.create(fozzy))); // this is meaningless, but kermit can do anything
        assertTrue(subject.isPermitted(AccountPermission.read(fozzy)));
        assertTrue(subject.isPermitted(AccountPermission.delete(fozzy)));

        // login as fozzy
        SecurityUtils.getSubject().login(new UsernamePasswordToken("fozzy", "fozzy1"));
        subject = SecurityUtils.getSubject();

        // what roles does fozzy have?
        assertFalse(subject.hasRole("admin"));
        assertTrue(subject.hasRole("member"));
        assertFalse(subject.hasRole("god"));

        // can fozzy generally do anything?
        assertTrue(subject.isPermitted(AccountPermission.create()));                                    // member implies "account:create"
        assertFalse(subject.isPermitted(AccountPermission.create(DomainPermissionEntity.ANY_TARGET)));  // no permission implies: "account:create:*"
        assertTrue(subject.isPermitted(AccountPermission.read()));                                      // member implies "account:read:*"
        assertTrue(subject.isPermitted(AccountPermission.read(DomainPermissionEntity.ANY_TARGET)));     // member implies "account:read:*"
        assertFalse(subject.isPermitted(AccountPermission.delete()));                                   // no permission implies "account:delete"
        assertFalse(subject.isPermitted(AccountPermission.delete(DomainPermissionEntity.ANY_TARGET)));  // no permission implies "account:delete:*"

        // can fozzy do stuff to his own account?
        assertFalse(subject.isPermitted(AccountPermission.create(fozzy)));  // this is meaningless, but technically no permissions implies "account:create:account-fozzy"
        assertTrue(subject.isPermitted(AccountPermission.read(fozzy)));     // member implies "account:read:*"
        assertTrue(subject.isPermitted(AccountPermission.delete(fozzy)));   // as fozzy: "account:delete:account-fozzy"

        // can fozzy do stuff to kermit's account?
        assertFalse(subject.isPermitted(AccountPermission.create(kermit))); // no permission implies "account:create:account-kermit"
        assertTrue(subject.isPermitted(AccountPermission.read(kermit)));    // member implies "account:read:*"
        assertFalse(subject.isPermitted(AccountPermission.delete(kermit))); // no permission implies "account:delete:account-kermit"
    }
}
