package com.springsecurity.weblogin.services.securityServices;

import com.springsecurity.weblogin.model.security.LoginFailure;
import com.springsecurity.weblogin.model.security.User;

import java.sql.Timestamp;
import java.util.List;

public interface LoginFailureService extends BaseService<LoginFailure, Long> {

    //handle lockout
    List<LoginFailure> findAllByUserAndCreatedDateIsAfter(User user, Timestamp timestamp);
}
