package com.springsecurity.weblogin.repositories.security;

import com.springsecurity.weblogin.model.security.LoginFailure;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LoginFailureRepository extends JpaRepository<LoginFailure, Long> {
}
