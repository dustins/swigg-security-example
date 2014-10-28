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

import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.springframework.boot.orm.jpa.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.persistence.EntityManager;

/**
 * @author Dustin Sweigart <dustin@swigg.net>
 */
@Configuration
@EntityScan({"net.swigg.security.authorization"})
public class AuthorizationConfig {
    @Bean
    public PermissionFetcher permissionFetcher(final EntityManager entityManager) {
        return new DomainPermissionFetcher(entityManager);
    }

    @Bean
    public RolePermissionResolver rolePermissionResolver(final EntityManager entityManager) {
        return new SecurityRolePermissionResolver(entityManager);
    }
}
