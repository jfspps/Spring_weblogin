package com.springsecurity.weblogin.listeners;

import com.springsecurity.weblogin.model.security.LoginFailure;
import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.repositories.security.LoginFailureRepository;
import com.springsecurity.weblogin.repositories.security.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Slf4j
@Component
public class AuthenticationFailureListener {

    private final LoginFailureRepository loginFailureRepository;

    private final UserRepository userRepository;

    @EventListener
    public void listen(AuthenticationFailureBadCredentialsEvent badCredentialsEvent){
        log.debug("Authentication error occurred");
        LoginFailure.LoginFailureBuilder failureBuilder = LoginFailure.builder();

        if (badCredentialsEvent.getSource() instanceof UsernamePasswordAuthenticationToken){
            UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) badCredentialsEvent.getSource();

            if (token.getPrincipal() instanceof String){
                String enteredUsername = (String) token.getPrincipal();
                failureBuilder.usernameEntered(enteredUsername);
                log.debug("Invalid login details entered, username: " + enteredUsername);
                if (userRepository.findByUsername(enteredUsername).isPresent()) {
                    User matchedUser = userRepository.findByUsername(enteredUsername).get();
                    failureBuilder.user(matchedUser);
                    log.debug("Username entered matches user with username: " + matchedUser.getUsername());
                } else {
                    log.debug("Username entered does not match any recorded username on file");
                }
            }

            if (token.getDetails() instanceof WebAuthenticationDetails){
                WebAuthenticationDetails details = (WebAuthenticationDetails) token.getDetails();
                failureBuilder.sourceIP(details.getRemoteAddress());
                log.debug("Unauthenticated user IP: " + details.getRemoteAddress());
            }
        }

        LoginFailure saved = loginFailureRepository.save(failureBuilder.build());
        log.debug("Login failure record saved, login record ID: " + saved.getId());
    }
}
