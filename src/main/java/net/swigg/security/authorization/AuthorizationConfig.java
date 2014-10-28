/*
 * Copyright
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
