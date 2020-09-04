package com.springsecurity.weblogin.services.securityServices;

import com.springsecurity.weblogin.model.security.GuardianUser;

public interface GuardianUserService extends BaseService<GuardianUser, Long>{
    GuardianUser findByGuardianUserName(String username);
}
