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

import static org.junit.Assert.*;

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
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setActions("action1");
        p2.setActions("action1");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1.setActions("action2");
        p2.setActions("action2");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));
    }

    @Test
    public void testImpliesNegativeSingleActions() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setActions("action1");
        p2.setActions("action2");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setActions("action2");
        p2.setActions("action1");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesAffirmativeMultiActions() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setActions("action1", "action2");
        p2.setActions("action1", "action2");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1.setActions("action2", "action1");
        p2.setActions("action2", "action1");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1.setActions("action1", "action2");
        p2.setActions("action2", "action1");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1.setActions("action2", "action1");
        p2.setActions("action1", "action2");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));
    }

    @Test
    public void testImpliesNegativeMultiActions() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setActions("action1", "action2");
        p2.setActions("action1", "action3");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setActions("action1", "action2");
        p2.setActions("action3", "action4");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setActions("action4", "action1");
        p2.setActions("action2", "action3");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setActions("action3", "action4");
        p2.setActions("action1", "action2");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setActions("action2", "action3");
        p2.setActions("action4", "action1");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesAffirmativeSingleInstance() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setTargets("instance1");
        p2.setTargets("instance1");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1.setTargets("instance2");
        p2.setTargets("instance2");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));
    }

    @Test
    public void testImpliesNegativeSingleInstance() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setTargets("instance1");
        p2.setTargets("instance2");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setTargets("instance2");
        p2.setTargets("instance1");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesAffirmativeMultiInstances() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setTargets("instance1", "instance2");
        p2.setTargets("instance1", "instance2");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1.setTargets("instance2", "instance1");
        p2.setTargets("instance2", "instance1");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1.setTargets("instance1", "instance2");
        p2.setTargets("instance2", "instance1");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1.setTargets("instance2", "instance1");
        p2.setTargets("instance1", "instance2");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));
    }

    @Test
    public void testImpliesNegativeMultiInstances() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setTargets("instance1", "instance2");
        p2.setTargets("instance1", "instance3");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setTargets("instance1", "instance2");
        p2.setTargets("instance3", "instance4");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setTargets("instance4", "instance1");
        p2.setTargets("instance2", "instance3");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setTargets("instance3", "instance4");
        p2.setTargets("instance1", "instance2");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setTargets("instance2", "instance3");
        p2.setTargets("instance4", "instance1");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesAffirmativeSingleAll() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setActions("action");
        p2.setActions("action");
        p1.setTargets("instance");
        p2.setTargets("instance");

        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));
    }

    @Test
    public void testImpliesNegativeSingleAll() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setActions("action2");
        p2.setActions("action1");
        p1.setTargets("instance1");
        p2.setTargets("instance1");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setActions("action1");
        p2.setActions("action2");
        p1.setTargets("instance1");
        p2.setTargets("instance1");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setActions("action1");
        p2.setActions("action1");
        p1.setTargets("instance2");
        p2.setTargets("instance1");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setActions("action1");
        p2.setActions("action1");
        p1.setTargets("instance1");
        p2.setTargets("instance2");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesAffirmativeMultiAll() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setActions("action1", "action2");
        p2.setActions("action1", "action2");
        p1.setTargets("instance1", "instance2");
        p2.setTargets("instance1", "instance2");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));

        p1.setActions("action1", "action2");
        p2.setActions("action2", "action1");
        p1.setTargets("instance1", "instance2");
        p2.setTargets("instance2", "instance1");
        assertTrue(p1.implies(p2));
        assertTrue(p2.implies(p1));;
    }

    @Test
    public void testImpliesNegativeMultiAll() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setActions("action1", "action2");
        p2.setActions("action1", "action3");
        p1.setTargets("instance1", "instance2");
        p2.setTargets("instance1", "instance2");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setActions("action1", "action2");
        p2.setActions("action1", "action2");
        p1.setTargets("instance1", "instance2");
        p2.setTargets("instance1", "instance3");
        assertFalse(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesWildCardActions() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setActions("*");
        p2.setActions("action");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesWildCardInstance() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setTargets("*");
        p2.setTargets("instance");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesWildCardMultiActions() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setActions("*");
        p2.setActions("action1", "action2");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setActions("*", "action3");
        p2.setActions("action1", "action2");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }

    @Test
    public void testImpliesWildCardMultiInstance() throws Exception {
        WildcardPermission p1 = new WildcardPermission("domain");
        WildcardPermission p2 = new WildcardPermission("domain");

        p1.setTargets("*");
        p2.setTargets("instance1", "instance2");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));

        p1.setTargets("*", "instance3");
        p2.setTargets("instance1", "instance2");
        assertTrue(p1.implies(p2));
        assertFalse(p2.implies(p1));
    }
}
