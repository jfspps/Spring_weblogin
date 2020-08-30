package com.springsecurity.weblogin.repositories.security;

import com.springsecurity.weblogin.model.security.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthorityRepository extends JpaRepository<Authority, Long> {
    // add custom JPA queries here
}
