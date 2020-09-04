package com.springsecurity.weblogin.repositories.security;

import com.springsecurity.weblogin.model.security.GuardianUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GuardianUserRepository extends JpaRepository<GuardianUser, Long>  {
}
