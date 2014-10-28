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
