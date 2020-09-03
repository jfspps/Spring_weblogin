package com.springsecurity.weblogin.services.springDataJPA;

import com.springsecurity.weblogin.model.security.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class TestRecordAuthenticationManager {
    //use in-context Authentication and match User's id on the DB

    public boolean userIdIsMatched(Authentication authentication, Long userId){
        User authenticatedUser = (User) authentication.getPrincipal();

        log.debug("AuthenticatedUser ID: " + authenticatedUser.getId() + ", supplied user ID: " + userId);

        return authenticatedUser.getId().equals(userId);
    }
}
