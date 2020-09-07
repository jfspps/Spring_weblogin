package com.springsecurity.weblogin.services.securityServices;

import com.springsecurity.weblogin.model.security.RootUser;

public interface RootUserService extends BaseService<RootUser, Long> {
    RootUser findByRootUserName(String username);
}
