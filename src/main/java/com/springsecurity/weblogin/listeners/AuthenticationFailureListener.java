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

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;

@RequiredArgsConstructor
@Slf4j
@Component
public class AuthenticationFailureListener {

    private final LoginFailureRepository loginFailureRepository;

    private final UserRepository userRepository;

    private final Integer LOCKOUTHOURS = 24;
    private final Integer LOGINATTEMPTS = 3;

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

        //manage automatic lockout
        if (saved.getUser() != null){
            lockAccount(saved.getUser());
        }
    }

    //note that failures persists even if the user logs in successfully before being locked out
    private void lockAccount(User user) {
        List<LoginFailure> failures = loginFailureRepository.findAllByUserAndCreatedDateIsAfter(user,
                Timestamp.valueOf(LocalDateTime.now().minusHours(LOCKOUTHOURS)));

        if(failures.size() > LOGINATTEMPTS){
            log.debug(LOGINATTEMPTS + " login attempts in the last " + LOCKOUTHOURS + " hours. Locking account.");
            user.setAccountNonLocked(false);
            userRepository.save(user);
        }
    }
}
