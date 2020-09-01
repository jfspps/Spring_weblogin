package com.springsecurity.weblogin.bootstrap.security;

import com.springsecurity.weblogin.model.security.Authority;
import com.springsecurity.weblogin.model.security.Role;
import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.repositories.security.AuthorityRepository;
import com.springsecurity.weblogin.repositories.security.RoleRepository;
import com.springsecurity.weblogin.repositories.security.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Component
@Slf4j
@Profile("SDjpa")
@RequiredArgsConstructor
public class DataLoader_SDjpa implements CommandLineRunner {

    private final UserRepository userRepository;
    private final AuthorityRepository authorityRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder DBpasswordEncoder = new BCryptPasswordEncoder();

    @Override
    public void run(String... args) {
        if (authorityRepository.findAll().size() == 0){
            populateH2();
            log.debug("Authority database finished populating");
        } else
            log.debug("Authority database already contains data; no changes made");
    }

    private void populateH2(){
        //this could be createStudent or createAssignment etc.
        Authority createObject = authorityRepository.save(Authority.builder().permission("object.create").build());
        Authority updateObject = authorityRepository.save(Authority.builder().permission("object.update").build());
        Authority readObject = authorityRepository.save(Authority.builder().permission("object.read").build());
        Authority deleteObject = authorityRepository.save(Authority.builder().permission("object.delete").build());

        Role admin = roleRepository.save(Role.builder().name("ADMIN").build());
        Role user = roleRepository.save(Role.builder().name("USER").build());
        Role teacher = roleRepository.save(Role.builder().name("TEACHER").build());
        Role guardian = roleRepository.save(Role.builder().name("GUARDIAN").build());

        //Set.Of returns an immutable set, so new HashSet instantiates a mutable Set
        admin.setAuthorities(new HashSet<>(Set.of(createObject, updateObject, readObject, deleteObject)));
        user.setAuthorities(new HashSet<>(Set.of(readObject)));
        teacher.setAuthorities(new HashSet<>(Set.of(createObject, updateObject, readObject, deleteObject)));
        guardian.setAuthorities(new HashSet<>(Set.of(readObject)));

//        //use ROLE_ prefix with JPAUserDetailsService; w/o ROLE_ prefix for in-memory
//        Authority userAuthority = authorityRepository.save(Authority.builder().role("ROLE_USER").build());
//        Authority teacherAuthority = authorityRepository.save(Authority.builder().role("ROLE_TEACHER").build());
//        Authority guardianAuthority = authorityRepository.save(Authority.builder().role("ROLE_GUARDIAN").build());

        roleRepository.saveAll(Arrays.asList(admin, user, teacher, guardian));

        log.debug("Roles added: " + roleRepository.count());
        log.debug("Authorities added: " + authorityRepository.count());

        userRepository.save(User.builder()
                .username("admin")
                .password(DBpasswordEncoder.encode("admin123"))
                .role(admin)
                .build());
        userRepository.save(User.builder()
                .username("user")
                .password(DBpasswordEncoder.encode("user123"))
                .role(user)
                .build());
        userRepository.save(User.builder()
                .username("teacher")
                .password(DBpasswordEncoder.encode("teacher123"))
                .role(teacher)
                .build());
        userRepository.save(User.builder()
                .username("guardian1")
                .password(DBpasswordEncoder.encode("guardian123"))
                .role(guardian)
                .build());
        userRepository.save(User.builder()
                .username("guardian2")
                .password(DBpasswordEncoder.encode("guardian456"))
                .role(guardian)
                .build());
        log.debug("Accounts added: " + userRepository.count());

        userRepository.findByUsername("admin").getAuthorities().forEach(authority ->
                System.out.println(authority.getPermission()));
    }
}
