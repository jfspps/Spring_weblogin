package com.springsecurity.weblogin.repositories.security;

import com.springsecurity.weblogin.model.security.AdminUser;
import com.springsecurity.weblogin.model.security.RootUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RootUserRepository extends JpaRepository<RootUser, Long> {
    Optional<RootUser> findByRootUserName(String username);
}
