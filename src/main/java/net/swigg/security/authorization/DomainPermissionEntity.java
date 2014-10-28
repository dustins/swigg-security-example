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

import com.google.common.base.Joiner;
import com.google.common.base.Objects;
import com.google.common.collect.Ordering;
import com.google.common.collect.Sets;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.util.StringUtils;

import javax.persistence.*;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;

import static com.google.common.base.Strings.emptyToNull;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
@Entity
public class DomainPermissionEntity extends WildcardPermission implements Permission {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id")
    private Long id;

    @Column(name = "securityIdentity")
    private String securityIdentity;

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

    public static TargetIdentity ANY_TARGET = new TargetIdentity() {
        @Override
        public String getTargetIdentityBase() {
            return "";
        }

        @Override
        public String getTargetIdentity() {
            return "*";
        }
    };

    /**
     * Creates a domain permission with *all* actions for *all* targets;
     */
    public DomainPermissionEntity() {
        this.actions = Sets.newTreeSet(Ordering.natural());
        this.targets = Sets.newTreeSet(Ordering.natural());
    }

    public DomainPermissionEntity(String domain) {
        this(domain, WILDCARD_TOKEN, WILDCARD_TOKEN);
    }

    public DomainPermissionEntity(String domain, String actions, String targets) {
        this();
        this.domain = domain;
        this.actions = StringUtils.splitToSet(actions, SUBPART_DIVIDER_TOKEN);
        this.targets = StringUtils.splitToSet(targets, SUBPART_DIVIDER_TOKEN);
        encodeParts(this.domain, actions, targets);
    }

    public DomainPermissionEntity(String domain, String actions) {
        this(domain, actions, "");
    }

    public DomainPermissionEntity(String domain, String actions, TargetIdentity target) {
        this(domain, actions, target.getTargetIdentity());
    }

    public DomainPermissionEntity(SecurityIdentity securityIdentity, String domain, String actions, String targets) {
        this(domain, actions, targets);
        this.securityIdentity = securityIdentity.getSecurityIdentity();
    }

    public DomainPermissionEntity(SecurityIdentity securityIdentity, String domain, String actions, TargetIdentity target) {
        this(securityIdentity, domain, actions, target.getTargetIdentity());
    }

    private void encodeParts(String domain, String actions, String targets) {
        if (!StringUtils.hasText(domain)) {
            throw new IllegalArgumentException("domain argument cannot be null or empty.");
        }
        StringBuilder sb = new StringBuilder(domain);

        if (!StringUtils.hasText(actions)) {
            if (StringUtils.hasText(targets)) {
                sb.append(PART_DIVIDER_TOKEN).append(WILDCARD_TOKEN);
            }
        } else {
            sb.append(PART_DIVIDER_TOKEN).append(actions);
        }
        if (StringUtils.hasText(targets)) {
            sb.append(PART_DIVIDER_TOKEN).append(targets);
        }
        setParts(sb.toString());
    }

    @Override
    protected List<Set<String>> getParts() {
        if (super.getParts() == null) {
            String actions = emptyToNull(Joiner.on(SUBPART_DIVIDER_TOKEN).join(this.actions));
            String targets = emptyToNull(Joiner.on(SUBPART_DIVIDER_TOKEN).join(this.targets));
            setParts(Joiner.on(PART_DIVIDER_TOKEN).useForNull(WILDCARD_TOKEN).join(this.domain, actions, targets));
        }

        return super.getParts();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSecurityIdentity() {
        return securityIdentity;
    }

    public void setSecurityIdentity(String securityIdentity) {
        this.securityIdentity = securityIdentity;
    }

    public String getDomain() {
        return domain;
    }

//    protected void setDomain(String domain) {
//        if (this.domain != null && this.domain.equals(domain)) {
//            return;
//        }
//        this.domain = domain;
//        setParts(domain, actions, targets);
//    }

    public Set<String> getActions() {
        return actions;
    }

//    protected void setActions(Set<String> actions) {
//        if (this.actions != null && this.actions.equals(actions)) {
//            return;
//        }
//        this.actions = actions;
//        setParts(domain, actions, targets);
//    }

    public Set<String> getTargets() {
        return targets;
    }

//    protected void setTargets(Set<String> targets) {
//        this.targets = targets;
//        if (this.targets != null && this.targets.equals(targets)) {
//            return;
//        }
//        this.targets = targets;
//        setParts(domain, actions, targets);
//    }

    @Override
    public int hashCode() {
        if (!SortedSet.class.isInstance(actions)) {
            SortedSet<String> sortedActions = Sets.newTreeSet(Ordering.natural());
            sortedActions.addAll(actions);
            this.actions = sortedActions;
        }

        if (!SortedSet.class.isInstance(targets)) {
            SortedSet<String> sortedTargets = Sets.newTreeSet(Ordering.natural());
            sortedTargets.addAll(targets);
            this.targets = sortedTargets;
        }

        return Objects.hashCode(id, domain, actions, targets);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        if (!super.equals(obj)) {
            return false;
        }
        final DomainPermissionEntity other = (DomainPermissionEntity) obj;
        return Objects.equal(this.id, other.id) && Objects.equal(this.domain, other.domain) && Objects.equal(this.actions, other.actions) && Objects.equal(this.targets, other.targets);
    }
}
