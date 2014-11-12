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

import com.google.common.base.Function;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import javax.annotation.Nullable;
import javax.persistence.*;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
@Entity
public class PrincipalWildcardPermission extends WildcardPermission {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id")
    private Long id;

    @Column(name = "principalIdentity")
    private String principalIdentity;

    @Column(name = "domain")
    private String domain;

    @ElementCollection(fetch = FetchType.EAGER)
    @Column(name = "name")
    @CollectionTable(name = "permission_action", joinColumns = @JoinColumn(name = "permission_id"))
    private Set<String> actions;

    @ElementCollection(fetch = FetchType.EAGER)
    @JoinColumn(name = "name")
    @CollectionTable(name = "permission_target", joinColumns = @JoinColumn(name = "permission_id"))
    private Set<String> targets;

    public PrincipalWildcardPermission(String permission) {
        super();

        List<String> parts = Splitter.on(DIVIDER).splitToList(permission);
        checkArgument(parts.size() > 0 && parts.size() <= 3);

        int x = 0;
        for (LEVEL level : LEVEL.values()) {
            if (x < parts.size()) {
                String part = parts.get(x);
                List<String> subdivisions = Splitter.on(SUBDIVIDER).splitToList(part);

                switch (level) {
                    case DOMAIN:
                        setDomain(part);
                        break;
                    case ACTION:
                        setActions(subdivisions);
                        break;
                    case TARGET:
                        setTargets(subdivisions);
                        break;
                }
            }

            x++;
        }
    }

    public PrincipalWildcardPermission(String domain, Collection<String> actions, Collection<String> instances) {
        super();

        this.setDomain(domain);
        this.setActions(actions);
        this.setTargets(instances);
    }

    public PrincipalWildcardPermission(String domain, Collection<String> actions, TargetIdentity... instances) {
        super();

        this.setDomain(domain);
        this.setActions(actions);
        this.setTargets(instances);
    }

    public PrincipalWildcardPermission(String principalIdentity, String permission) {
        this(permission);
        this.principalIdentity = checkNotNull(principalIdentity);
    }

    public PrincipalWildcardPermission(PrincipalIdentity principalIdentity, String permission) {
        this(principalIdentity.getPrincipalIdentity(), permission);
    }

    public PrincipalWildcardPermission(String principalIdentity, String domain, Collection<String> actions, Collection<String> instances) {
        this(domain, actions, instances);
        this.principalIdentity = checkNotNull(principalIdentity);
    }

    public PrincipalWildcardPermission(String principalIdentity, String domain, Collection<String> actions, TargetIdentity... instances) {
        this(domain, actions, instances);
        this.principalIdentity = checkNotNull(principalIdentity);
    }

    public PrincipalWildcardPermission(PrincipalIdentity principalIdentity, String domain, Collection<String> actions, Collection<String> instances) {
        this(principalIdentity.getPrincipalIdentity(), domain, actions, instances);
    }

    public PrincipalWildcardPermission(PrincipalIdentity principalIdentity, String domain, Collection<String> actions, TargetIdentity... instances) {
        this(principalIdentity.getPrincipalIdentity(), domain, actions, instances);
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getPrincipalIdentity() {
        return principalIdentity;
    }

    public void setPrincipalIdentity(String principalIdentity) {
        this.principalIdentity = principalIdentity;
    }

    public String getDomain() {
        return domain;
    }

    @Override
    protected void setDomain(String domain) {
        this.domain = checkNotNull(domain);
        super.setDomain(this.domain);
    }

    public ImmutableSet<String> getActions() {
        return ImmutableSet.copyOf(this.actions);
    }

    public PrincipalWildcardPermission setActions(Collection<String> actions) {
        this.actions = actions != null ? Sets.newHashSet(actions) : Sets.newHashSet(WILDCARD);
        super.setActions(this.actions.toArray(new String[this.actions.size()]));
        return this;
    }

    public ImmutableSet<String> getTargets() {
        return ImmutableSet.copyOf(targets);
    }

    public PrincipalWildcardPermission setTargets(Collection<String> targets) {
        this.targets = targets != null ? Sets.newHashSet(targets) : Sets.newHashSet(WILDCARD);
        super.setTargets(this.targets.toArray(new String[this.targets.size()]));
        return this;
    }

    public PrincipalWildcardPermission setTargets(TargetIdentity... targets) {
        this.setTargets(Lists.transform(Arrays.asList(targets), new Function<TargetIdentity, String>() {
            @Nullable
            @Override
            public String apply(TargetIdentity input) {
                return input.getTargetIdentity();
            }
        }));
        return this;
    }
}
