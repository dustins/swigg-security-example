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

package net.swigg.security.authorization;

import com.google.common.collect.Lists;
import org.apache.shiro.authz.Permission;
import org.joda.time.DateTime;
import org.joda.time.Interval;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class PermissionSpeedTest {
    static private final Logger LOGGER = LoggerFactory.getLogger(PermissionSpeedTest.class);

    @Test
    public void testShiroWildcardPermission() throws Exception {
        DateTime startDate = DateTime.now();
        for (int x = 0; x < 100000; x++) {
            Permission p1 = new org.apache.shiro.authz.permission.WildcardPermission("*:*:*");
            Permission p2 = new org.apache.shiro.authz.permission.WildcardPermission("domain:*:*");
            Permission p3 = new org.apache.shiro.authz.permission.WildcardPermission("domain:action1:*");
            Permission p4 = new org.apache.shiro.authz.permission.WildcardPermission("domain:action1:instance1");
            Permission p5 = new org.apache.shiro.authz.permission.WildcardPermission("domain:action1,action2:*");
            Permission p6 = new org.apache.shiro.authz.permission.WildcardPermission("domain:action1:instance1,instance2");

            List<Permission> permissions = Lists.newArrayList(p1, p2, p3, p4, p5, p6);
            for (Permission perm1 : permissions) {
                for (Permission perm2 : permissions) {
                    perm1.implies(perm2);
                    perm2.implies(perm1);
                }
            }
        }
        DateTime endDate = DateTime.now();
        System.out.println(String.format("ShiroWildcardPermission took %s", new Interval(startDate, endDate).toPeriod()));
    }

    @Test
    public void testSwiggWildcardPermission() throws Exception {
        DateTime startDate = DateTime.now();
        for (int x = 0; x < 100000; x++) {
            Permission p1 = new WildcardPermission("*:*:*");
            Permission p2 = new WildcardPermission("domain:*:*");
            Permission p3 = new WildcardPermission("domain:action1:*");
            Permission p4 = new WildcardPermission("domain:action1:instance1");
            Permission p5 = new WildcardPermission("domain:action1,action2:*");
            Permission p6 = new WildcardPermission("domain:action1:instance1,instance2");

            List<Permission> permissions = Lists.newArrayList(p1, p2, p3, p4, p5, p6);
            for (Permission perm1 : permissions) {
                for (Permission perm2 : permissions) {
                    perm1.implies(perm2);
                    perm2.implies(perm1);
                }
            }
        }
        DateTime endDate = DateTime.now();
        System.out.println(String.format("SwiggWildcardPermission took %s", new Interval(startDate, endDate).toPeriod()));
    }
}
