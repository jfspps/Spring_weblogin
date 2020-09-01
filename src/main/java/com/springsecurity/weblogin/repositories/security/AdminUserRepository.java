package com.springsecurity.weblogin.repositories.security;

import com.springsecurity.weblogin.model.security.AdminUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AdminUserRepository extends JpaRepository<AdminUser, Long> {
    //add more custom JPA methods here
}
