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

import org.apache.shiro.authz.Permission;

import java.util.Collection;
import java.util.Set;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public interface PermissionFetcher {
    /**
     * Returns {@link Permission}s that are owned by one of the {@link PrincipalIdentity}s.
     *
     * @param identities
     * @param permissions
     * @return
     */
    Set<? extends Permission> fetchPermissions(Collection<PrincipalIdentity> identities, Permission... permissions);
}
