package com.springsecurity.weblogin.repositories.security;

import com.springsecurity.weblogin.model.security.LoginSuccess;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LoginSuccessRepository extends JpaRepository<LoginSuccess, Long> {
}
