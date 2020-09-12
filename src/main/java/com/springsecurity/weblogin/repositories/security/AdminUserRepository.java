package com.springsecurity.weblogin.repositories.security;

import com.springsecurity.weblogin.model.security.AdminUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.Set;

public interface AdminUserRepository extends JpaRepository<AdminUser, Long> {
    Optional<AdminUser> findByAdminUserName(String username);

    Set<AdminUser> findAllByAdminUserName(String userName);
}
