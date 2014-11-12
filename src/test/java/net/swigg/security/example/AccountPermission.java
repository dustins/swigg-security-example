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
import net.swigg.security.authorization.DATPermission;
import net.swigg.security.authorization.TargetIdentity;
import net.swigg.security.authorization.WildcardPermission;
import org.apache.shiro.authz.Permission;

import java.util.Set;

/**
 * Implementation of {@link org.apache.shiro.authz.Permission} specifically for {@link Account}s.
 *
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class AccountPermission extends DATPermission implements Permission {
    public static final String PERMISSION_DOMAIN = "account";

    private Set<String> actions;

    public AccountPermission(TargetIdentity... identities) {
        super(PERMISSION_DOMAIN, null, identities);
        this.actions = Sets.newHashSet();
    }

    public WildcardPermission create() {
        this.actions.add("create");
        this.setActions(this.actions);
        return this;
    }

    public WildcardPermission read() {
        this.actions.add("read");
        this.setActions(this.actions);
        return this;
    }

    public WildcardPermission delete() {
        this.actions.add("delete");
        this.setActions(this.actions);
        return this;
    }
}
