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

/**
 * Interface that classes can implement to identify themselves when being referenced as the target of a permission.
 *
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public interface TargetIdentity {
    /**
     * The unique identity of this resource. Identities should not be built using user configurable attributes for
     * security reasons. A target identity for a post in a blog application might return "post-4" which is built by
     * pre-pending a meaningful type with a database assigned numeric id.
     *
     * @return
     */
    String getTargetIdentity();

    public static TargetIdentity ANY = new TargetIdentity() {
        @Override
        public String getTargetIdentity() {
            return "*";
        }
    };
}
