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
 * Permission based on the premise of {@link org.apache.shiro.authz.permission.WildcardPermission}
 *
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class WildcardPermission implements Permission {
    protected static final String WILDCARD = "*";
    protected static final String DIVIDER = ":";
    protected static final String SUBDIVIDER = ",";

    public static enum LEVEL {
        DOMAIN, ACTION, TARGET
    }

    private final Map<LEVEL, Integer> levelHash;

    private final Map<LEVEL, Boolean> levelWildcard;

    /**
     * Designated constructor.
     */
    protected WildcardPermission() {
        this.levelHash = Maps.newHashMap();
        this.levelWildcard = Maps.newHashMap();
    }

    public WildcardPermission(String domain, Collection<String> actions, Collection<String> targets) {
        this();

        levelHash(LEVEL.DOMAIN, domain);
        levelHash(LEVEL.ACTION, actions);
        levelHash(LEVEL.TARGET, targets);
    }

    public WildcardPermission(String permission) {
        this();

//        List<String> parts = Splitter.on(DIVIDER).splitToList(permission);
        List<String> parts = CollectionUtils.asList(permission.split(DIVIDER));
//        checkArgument(parts.size() > 0 && parts.size() <= 3);

        int x = 0;
        for (LEVEL level : LEVEL.values()) {
            if (x < parts.size()) {
                String part = parts.get(x);
//                List<String> subdivisions = Splitter.on(SUBDIVIDER).splitToList(part);
                List<String> subdivisions = CollectionUtils.asList(part.split(SUBDIVIDER));
//                if (level.equals(LEVEL.DOMAIN) && subdivisions.size() > 1) {
//                    throw new IllegalArgumentException("Permission string can't have multiple domains");
//                }
                levelHash(level, subdivisions.toArray(new String[subdivisions.size()]));
            } else {
                levelHash(level, WILDCARD);
            }

            x++;
        }
    }

    public Map<LEVEL, Integer> getLevelHash() {
        return levelHash;
    }

    protected void setDomain(String domain) {
        levelHash(LEVEL.DOMAIN, domain);
    }

    public void setActions(String... actions) {
        levelHash(LEVEL.ACTION, actions);
    }

    public void setTargets(String... targets) {
        levelHash(LEVEL.TARGET, targets);
    }

    private int levelHash(LEVEL level, String... items) {
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

    private int levelHash(LEVEL level, Collection<String> items) {
        items = items != null ? items : Collections.<String>emptyList();
        return levelHash(level, items.toArray(new String[items.size()]));
    }

    @Override
    public boolean implies(Permission p) {
        if (!WildcardPermission.class.isInstance(p)) {
            return false;
        }

        WildcardPermission that = WildcardPermission.class.cast(p);
        for (LEVEL level : LEVEL.values()) {
            if (!this.levelWildcard.get(level)) {
                if (!this.levelHash.get(level).equals(that.levelHash.get(level))) {
                    return false;
                }
            }
        }

        return true;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("domain", this.levelHash.get(LEVEL.DOMAIN))
                .add("actions", this.levelHash.get(LEVEL.ACTION))
                .add("targets", this.levelHash.get(LEVEL.TARGET))
                .toString();
    }
}
