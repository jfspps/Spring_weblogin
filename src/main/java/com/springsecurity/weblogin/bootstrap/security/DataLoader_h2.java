package com.springsecurity.weblogin.bootstrap.security;

import com.springsecurity.weblogin.model.security.Authority;
import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.services.securityServices.AuthorityService;
import com.springsecurity.weblogin.services.securityServices.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@Profile("map")
@RequiredArgsConstructor
public class DataLoader_h2 implements CommandLineRunner {

    private final UserService userService;
    private final AuthorityService authorityService;
    private final PasswordEncoder DBpasswordEncoder = new BCryptPasswordEncoder();

    @Override
    public void run(String... args) {
        if (authorityService.findAll().isEmpty()){
            populateH2();
            log.debug("Authority database finished populating");
        } else
            log.debug("Authority database already contains data; no changes made");
    }

    private void populateH2(){
        //example, as per Student Record Management (SRM) account
        Authority adminAuthority = authorityService.save(Authority.builder().role("ADMIN").build());
        Authority teacherAuthority = authorityService.save(Authority.builder().role("TEACHER").build());
        Authority guardianAuthority = authorityService.save(Authority.builder().role("GUARDIAN").build());
        log.debug("Authorities added: " + authorityService.findAll().size());

        userService.save(User.builder()
                .username("admin")
                .password(DBpasswordEncoder.encode("admin123"))
                .authority(adminAuthority)  //singular set, courtesy of Project Lombok
                .build());
        userService.save(User.builder()
                .username("user")
                .password(DBpasswordEncoder.encode("user123"))
                .authority(teacherAuthority)
                .build());
        userService.save(User.builder()
                .username("guardian1")
                .password(DBpasswordEncoder.encode("guardian123"))
                .authority(guardianAuthority)
                .build());
        userService.save(User.builder()
                .username("guardian2")
                .password(DBpasswordEncoder.encode("guardian456"))
                .authority(guardianAuthority)
                .build());
        log.debug("Users added: " + userService.findAll().size());
    }
}
