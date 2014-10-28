/*
 * Copyright
 */

package net.swigg.security.authorization;

import com.google.common.collect.Lists;
import com.mysema.query.jpa.impl.JPAQuery;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.RolePermissionResolver;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.Collection;
import java.util.List;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
public class SecurityRolePermissionResolver implements RolePermissionResolver {
    @PersistenceContext
    private final EntityManager entityManager;

    public SecurityRolePermissionResolver(final EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public Collection<Permission> resolvePermissionsInRole(String roleString) {
        QDomainPermissionEntity domainPermissionEntity = QDomainPermissionEntity.domainPermissionEntity;
        JPAQuery query = new JPAQuery(getEntityManager());
        List<? extends Permission> permissions = query.from(domainPermissionEntity)
                .where(domainPermissionEntity.securityIdentity.eq(roleString)).list(domainPermissionEntity);

        return Lists.newArrayList(permissions);
    }

    public EntityManager getEntityManager() {
        return entityManager;
    }
}
