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

import com.google.common.collect.Sets;
import com.mysema.query.jpa.impl.JPAQuery;
import com.mysema.query.types.expr.BooleanExpression;
import org.apache.shiro.authz.Permission;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * JPA based implementation of {@link PermissionFetcher} that uses QueryDSL
 *
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class DATPermissionFetcher implements PermissionFetcher {
    @PersistenceContext
    private final EntityManager entityManager;

    public DATPermissionFetcher(final EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Transactional(readOnly = true)
    public Set<? extends Permission> fetchPermissions(Collection<PrincipalIdentity> identities, Permission... permissions) {
        QDATPermission wcPerm = new QDATPermission("permission");

        // create the query
        JPAQuery query = new JPAQuery(getEntityManager());
        query.from(wcPerm);

        BooleanExpression whereExpression = null;
        // build predicate for each principalIdentity case
        for (PrincipalIdentity identity : identities) {
            BooleanExpression pidExpression = wcPerm.principalIdentity.eq(identity.getPrincipalIdentity());

            BooleanExpression permScopeExpr = null;
            for (Permission permission : permissions) {
                if (DATPermission.class.isInstance(permission)) {
                    DATPermission queryPermission = DATPermission.class.cast(permission);
                    String domain = queryPermission.getDomain();
                    Set<String> actions = Sets.newHashSet(queryPermission.getActions());
                    Set<String> targets = Sets.newHashSet(queryPermission.getTargets());

                    BooleanExpression permExpression = wcPerm.domain.in(domain, "*");

                    if (actions.size() > 0) {
                        actions.add("*");
                        permExpression = permExpression.and(wcPerm.actions.any().in(actions));
                    }

                    if (targets.size() > 0) {
                        targets.add("*");
                        permExpression = permExpression.and(wcPerm.targets.any().in(targets));
                    }

                    permScopeExpr = (permScopeExpr == null) ? permExpression : permScopeExpr.or(permExpression);
                }
            }

            pidExpression = pidExpression.and(permScopeExpr);
            whereExpression = (whereExpression == null) ? pidExpression : whereExpression.or(pidExpression);
        }

        List<? extends Permission> queryPermissions = query.where(whereExpression).list(wcPerm);
        Set<Permission> permissionSet = Sets.newHashSet(queryPermissions);
        return permissionSet;
    }

    public EntityManager getEntityManager() {
        return entityManager;
    }
}
