package com.springsecurity.weblogin.services.securityServices;

import com.springsecurity.weblogin.model.security.AdminUser;

import java.util.Set;

public interface AdminUserService extends BaseService<AdminUser, Long> {
    AdminUser findByAdminUserName(String username);

    Set<AdminUser> findAllByAdminUserName(String userName);
}
