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

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class WildcardPermissionTest {
    @Test
    public void testImpliesAffirmativeDomain() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));
    }

    @Test
    public void testImpliesNegativeDomain() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain1");
        WildcardPermission p2 = new WildcardPermission("domain2");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesAffirmativeSingleActions() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:action1");
        WildcardPermission p2 = new WildcardPermission("domain:action1");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1 = new WildcardPermission("domain:action2");
        p2 = new WildcardPermission("domain:action2");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));
    }

    @Test
    public void testImpliesNegativeSingleActions() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:action1");
        WildcardPermission p2 = new WildcardPermission("domain:action2");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:action2");
        p2 = new WildcardPermission("domain:action1");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesAffirmativeMultiActions() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:action1,action2");
        WildcardPermission p2 = new WildcardPermission("domain:action1,action2");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1 = new WildcardPermission("domain:action2,action1");
        p2 = new WildcardPermission("domain:action2,action1");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1 = new WildcardPermission("domain:action1,action2");
        p2 = new WildcardPermission("domain:action2,action1");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1 = new WildcardPermission("domain:action2,action1");
        p2 = new WildcardPermission("domain:action1,action2");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));
    }

    @Test
    public void testImpliesNegativeMultiActions() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:action1,action2");
        WildcardPermission p2 = new WildcardPermission("domain:action1,action3");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:action1,action2");
        p2 = new WildcardPermission("domain:action3,action4");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:action4,action1");
        p2 = new WildcardPermission("domain:action2,action3");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:action3,action4");
        p2 = new WildcardPermission("domain:action1,action2");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:action2,action3");
        p2 = new WildcardPermission("domain:action4,action1");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesAffirmativeSingleInstance() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:*:instance1");
        WildcardPermission p2 = new WildcardPermission("domain:*:instance1");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1 = new WildcardPermission("domain:*:instance2");
        p2 = new WildcardPermission("domain:*:instance2");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));
    }

    @Test
    public void testImpliesNegativeSingleInstance() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:*:instance1");
        WildcardPermission p2 = new WildcardPermission("domain:*:instance2");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:*:instance2");
        p2 = new WildcardPermission("domain:*:instance1");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesAffirmativeMultiInstances() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:*:instance1,instance2");
        WildcardPermission p2 = new WildcardPermission("domain:*:instance1,instance2");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1 = new WildcardPermission("domain:*:instance2,instance1");
        p2 = new WildcardPermission("domain:*:instance2,instance1");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1 = new WildcardPermission("domain:*:instance1,instance2");
        p2 = new WildcardPermission("domain:*:instance2,instance1");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1 = new WildcardPermission("domain:*:instance2,instance1");
        p2 = new WildcardPermission("domain:*:instance1,instance2");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));
    }

    @Test
    public void testImpliesNegativeMultiInstances() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:*:instance1,instance2");
        WildcardPermission p2 = new WildcardPermission("domain:*:instance1,instance3");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:*:instance1,instance2");
        p2 = new WildcardPermission("domain:*:instance3,instance4");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:*:instance4,instance1");
        p2 = new WildcardPermission("domain:*:instance2,instance3");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:*:instance3,instance4");
        p2 = new WildcardPermission("domain:*:instance1,instance2");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:*:instance2,instance3");
        p2 = new WildcardPermission("domain:*:instance4,instance1");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesAffirmativeSingleAll() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:action:instance");
        WildcardPermission p2 = new WildcardPermission("domain:action:instance");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));
    }

    @Test
    public void testImpliesNegativeSingleAll() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:action2:instance1");
        WildcardPermission p2 = new WildcardPermission("domain:action1:instance1");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:action1:instance1");
        p2 = new WildcardPermission("domain:action2:instance1");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:action1:instance2");
        p2 = new WildcardPermission("domain:action1:instance1");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:action1:instance1");
        p2 = new WildcardPermission("domain:action1:instance2");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesAffirmativeMultiAll() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:action1,action2:instance1,instance2");
        WildcardPermission p2 = new WildcardPermission("domain:action1,action2:instance1,instance2");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1 = new WildcardPermission("domain:action1,action2:instance1,instance2");
        p2 = new WildcardPermission("domain:action2,action1:instance2,instance1");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));;
    }

    @Test
    public void testImpliesNegativeMultiAll() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:action1,action2:instance1,instance2");
        WildcardPermission p2 = new WildcardPermission("domain:action1,action3:instance1,instance2");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:action1,action2:instance1,instance2");
        p2 = new WildcardPermission("domain:action1,action2:instance1,instance3");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesWildCardActions() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:*");
        WildcardPermission p2 = new WildcardPermission("domain:action");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesWildCardInstance() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:*:*");
        WildcardPermission p2 = new WildcardPermission("domain:*:instance");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesWildCardMultiActions() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:*");
        WildcardPermission p2 = new WildcardPermission("domain:action1,action2");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:*,action3");
        p2 = new WildcardPermission("domain:action1,action2");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesWildCardMultiInstance() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain:*:*");
        WildcardPermission p2 = new WildcardPermission("domain:*:instance1,instance2");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:*:*,instance3");
        p2 = new WildcardPermission("domain:*:instance1,instance2");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesUnbalanced() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain:action1");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain");
        p2 = new WildcardPermission("domain:action1,action2:instance1,instance2");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1 = new WildcardPermission("domain:*:instance1,instance2");
        p2 = new WildcardPermission("domain:action1,action2:instance1,instance2");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }
}
