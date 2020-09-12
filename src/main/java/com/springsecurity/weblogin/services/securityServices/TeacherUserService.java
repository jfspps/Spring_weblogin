package com.springsecurity.weblogin.services.securityServices;

import com.springsecurity.weblogin.model.security.TeacherUser;

import java.util.Set;

public interface TeacherUserService extends BaseService<TeacherUser, Long>{
    TeacherUser findByTeacherUserName(String username);

    Set<TeacherUser> findAllByTeacherUserName(String userName);
}
