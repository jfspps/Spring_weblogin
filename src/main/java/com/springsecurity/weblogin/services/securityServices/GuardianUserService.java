package com.springsecurity.weblogin.services.securityServices;

import com.springsecurity.weblogin.model.security.GuardianUser;

import java.util.Set;

public interface GuardianUserService extends BaseService<GuardianUser, Long>{
    GuardianUser findByGuardianUserName(String username);

    Set<GuardianUser> findAllByGuardianUserName(String userName);
}
