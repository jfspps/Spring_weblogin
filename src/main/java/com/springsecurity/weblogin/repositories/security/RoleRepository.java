package com.springsecurity.weblogin.repositories.security;

import com.springsecurity.weblogin.model.security.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    // add custom JPA queries here
    Role findByRoleName(String roleName);
}
