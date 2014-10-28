/*
 * Copyright
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
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class DomainPermissionFetcher implements PermissionFetcher {
    @PersistenceContext
    private final EntityManager entityManager;

    public DomainPermissionFetcher(final EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Transactional(readOnly = true)
    public Set<? extends Permission> fetchPermissions(Collection<String> securityIdentities, Permission... permissions) {
        QDomainPermissionEntity wcPerm = new QDomainPermissionEntity("permission");

        // create the query
        JPAQuery query = new JPAQuery(getEntityManager());
        query.from(wcPerm);

        BooleanExpression whereExpression = null;
        // build predicate for each securityIdentity case
        for (String securityIdentity : securityIdentities) {
            BooleanExpression sidExpression = wcPerm.securityIdentity.eq(securityIdentity);

            BooleanExpression permScopeExpr = null;
            for (Permission permission : permissions) {
                if (DomainPermissionEntity.class.isInstance(permission)) {
                    DomainPermissionEntity queryPermission = DomainPermissionEntity.class.cast(permission);
                    String domain = queryPermission.getDomain();
                    Set<String> actions = queryPermission.getActions();
                    Set<String> targets = queryPermission.getTargets();

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

            sidExpression = sidExpression.and(permScopeExpr);
            whereExpression = (whereExpression == null) ? sidExpression : whereExpression.or(sidExpression);
        }

        List<? extends Permission> queryPermissions = query.where(whereExpression).list(wcPerm);
        Set<Permission> permissionSet = Sets.newHashSet(queryPermissions);
        return permissionSet;
    }

    public EntityManager getEntityManager() {
        return entityManager;
    }
}
