package com.springsecurity.weblogin.listeners;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthenticationFailureListener {

    @EventListener
    public void listen(AuthenticationFailureBadCredentialsEvent badCredentialsEvent){
        log.debug("Authentication error occurred");

        if (badCredentialsEvent.getSource() instanceof UsernamePasswordAuthenticationToken){
            UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) badCredentialsEvent.getSource();

            if (token.getPrincipal() instanceof String){
                log.debug("Invalid login details entered, username: " + token.getPrincipal());
            }

            if (token.getDetails() instanceof WebAuthenticationDetails){
                WebAuthenticationDetails details = (WebAuthenticationDetails) token.getDetails();
                log.debug("Unauthenticated user IP: " + details.getRemoteAddress());
            }
        }
    }
}
