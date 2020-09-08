package com.springsecurity.weblogin.listeners;

import com.springsecurity.weblogin.model.security.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AuthenticationSuccessListener {

    //executes when successful events occur
    @EventListener
    public void listen(AuthenticationSuccessEvent successEvent){
        log.debug("Authentication successful");

        //check the type of the successEvent before casting, and then extract properties
        if (successEvent.getSource() instanceof UsernamePasswordAuthenticationToken){
            UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) successEvent.getSource();

            //successEvent.source holds principal and some credentials
            if (token.getPrincipal() instanceof User){
                User user = (User) token.getPrincipal();
                log.debug("Username: " + user.getUsername() + " logged in");
            }

            if (token.getDetails() instanceof WebAuthenticationDetails){
                WebAuthenticationDetails details = (WebAuthenticationDetails) token.getDetails();
                log.debug("User IP: " + details.getRemoteAddress());
            }
        }
    }
}
