package com.springsecurity.weblogin.repositories.security;

import com.springsecurity.weblogin.model.security.GuardianUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.Set;

public interface GuardianUserRepository extends JpaRepository<GuardianUser, Long>  {
    Optional<GuardianUser> findByGuardianUserName(String username);

    Set<GuardianUser> findAllByGuardianUserName(String userName);
}
