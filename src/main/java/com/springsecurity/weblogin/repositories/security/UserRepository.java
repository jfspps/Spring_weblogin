package com.springsecurity.weblogin.repositories.security;

import com.springsecurity.weblogin.model.security.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    // add custom JPA queries here
    User findByUsername(String username);
}
