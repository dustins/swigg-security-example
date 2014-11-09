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

import net.swigg.security.authorization.PrincipalIdentity;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class Role implements PrincipalIdentity {
    private String name;

    public Role(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    @Override
    public String getPrincipalIdentity() {
        return "role:" + getName();
    }
}
