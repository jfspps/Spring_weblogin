package com.springsecurity.weblogin.services.securityServices;

import com.springsecurity.weblogin.model.security.TeacherUser;

public interface TeacherUserService extends BaseService<TeacherUser, Long>{
    TeacherUser findByTeacherUserName(String username);
}
