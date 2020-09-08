package com.springsecurity.weblogin.listeners;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthenticationSuccessListener {

    //executes when successful events occur
    @EventListener
    public void listen(AuthenticationSuccessEvent authenticationSuccessEvent){
        log.debug("Something worked!");
    }
}
