package com.springsecurity.weblogin.repositories.security;

import com.springsecurity.weblogin.model.security.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    // add custom JPA queries here
    Optional<User> findByUsername(String username);
}
