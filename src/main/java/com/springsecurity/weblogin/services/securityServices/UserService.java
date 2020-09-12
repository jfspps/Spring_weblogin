package com.springsecurity.weblogin.services.securityServices;

import com.springsecurity.weblogin.model.security.User;

import java.util.Set;

public interface UserService extends BaseService<User, Long> {
    // declare custom (map-related) query methods here
    User findByUsername(String username);

    Set<User> findAllByUsername(String username);
}
