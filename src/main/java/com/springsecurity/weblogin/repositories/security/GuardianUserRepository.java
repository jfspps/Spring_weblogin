package com.springsecurity.weblogin.repositories.security;

import com.springsecurity.weblogin.model.security.GuardianUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface GuardianUserRepository extends JpaRepository<GuardianUser, Long>  {
    Optional<GuardianUser> findByGuardianUserName(String username);
}
