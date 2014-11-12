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

import com.google.common.base.MoreObjects;
import com.google.common.collect.Maps;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.util.CollectionUtils;

import java.util.*;

/**
 * Permission based on the premise of {@link org.apache.shiro.authz.permission.WildcardPermission}, but using precomputed
 * value hashes when running {@link #implies(Permission)}.
 *
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class WildcardPermission implements Permission {
    protected static final String WILDCARD = "*";
    protected static final String DIVIDER = ":";
    protected static final String SUBDIVIDER = ",";

    private final Map<Integer, Integer> levelHash;

    private final Map<Integer, Boolean> levelWildcard;

    /**
     * Designated constructor.
     */
    protected WildcardPermission() {
        this.levelHash = Maps.newHashMap();
        this.levelWildcard = Maps.newHashMap();
    }

    public WildcardPermission(String permission) {
        this();

        String[] parts = permission.split(DIVIDER);

        int x = 0;
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) {
                throw new IllegalArgumentException("Wildcard parts can not be empty.");
            }
            List<String> subdivisions = CollectionUtils.asList(trimmed.split(SUBDIVIDER));
            levelHash(x, subdivisions.toArray(new String[subdivisions.size()]));
            x++;
        }
    }

    public Map<Integer, Integer> getLevelHash() {
        return levelHash;
    }

    protected int levelHash(Integer level, String... items) {
        if (items == null || items.length == 0) {
            items = new String[]{WILDCARD};
        }

        Boolean isWildcard = false;
        Arrays.sort(items);
        int levelValue = Arrays.hashCode(items);
        for (String item : items) {
            isWildcard = isWildcard || WILDCARD.equals(item);
        }

        this.levelHash.put(level, levelValue);
        this.levelWildcard.put(level, isWildcard);

        return levelValue;
    }

    protected int levelHash(Integer level, Collection<String> items) {
        items = items != null ? items : Collections.<String>emptyList();
        return levelHash(level, items.toArray(new String[items.size()]));
    }

    @Override
    public boolean implies(Permission p) {
        if (!WildcardPermission.class.isInstance(p)) {
            return false;
        }

        WildcardPermission that = WildcardPermission.class.cast(p);
        for (Integer x : this.levelHash.keySet()) {
            if (!this.levelWildcard.get(x)) {
                if (that.levelHash.size() < x) {
                    return false;
                }

                if (!this.levelHash.get(x).equals(that.levelHash.get((x)))) {
                    return false;
                }
            }
        }

        return true;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("levelHash", this.levelHash.values().toArray(new Integer[this.levelHash.size()]))
                .toString();
    }
}
