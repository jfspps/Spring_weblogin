package com.springsecurity.weblogin.bootstrap.security;

import com.springsecurity.weblogin.model.security.Authority;
import com.springsecurity.weblogin.model.security.Role;
import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.services.securityServices.AuthorityService;
import com.springsecurity.weblogin.services.securityServices.RoleService;
import com.springsecurity.weblogin.services.securityServices.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
@Slf4j
@RequiredArgsConstructor
@Profile("map")
public class DataLoader_h2 implements CommandLineRunner {

    private final UserService userService;
    private final AuthorityService authorityService;
    private final RoleService roleService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        log.debug("Users on file: " + userService.findAll().size());
        log.debug("Authorities on file: " + authorityService.findAll().size());
        log.debug("Roles on file: " + roleService.findAll().size());

        if (userService.findAll().size() == 0){
            populateH2();
            log.debug("Users database finished populating");
        } else
            log.debug("Users database already contains data; no changes made");
    }

    private void populateH2(){
        //admin authorities
        Authority createAdmin = authorityService.save(Authority.builder().permission("admin.create").build());
        Authority updateAdmin = authorityService.save(Authority.builder().permission("admin.update").build());
        Authority readAdmin = authorityService.save(Authority.builder().permission("admin.read").build());
        Authority deleteAdmin = authorityService.save(Authority.builder().permission("admin.delete").build());

        //user authorities
        Authority createUser = authorityService.save(Authority.builder().permission("user.create").build());
        Authority updateUser = authorityService.save(Authority.builder().permission("user.update").build());
        Authority readUser = authorityService.save(Authority.builder().permission("user.read").build());
        Authority deleteUser = authorityService.save(Authority.builder().permission("user.delete").build());

        //teacher authorities
        Authority createTeacher = authorityService.save(Authority.builder().permission("teacher.create").build());
        Authority updateTeacher = authorityService.save(Authority.builder().permission("teacher.update").build());
        Authority readTeacher = authorityService.save(Authority.builder().permission("teacher.read").build());
        Authority deleteTeacher = authorityService.save(Authority.builder().permission("teacher.delete").build());

        //guardian authorities
        Authority createGuardian = authorityService.save(Authority.builder().permission("guardian.create").build());
        Authority updateGuardian = authorityService.save(Authority.builder().permission("guardian.update").build());
        Authority readGuardian = authorityService.save(Authority.builder().permission("guardian.read").build());
        Authority deleteGuardian = authorityService.save(Authority.builder().permission("guardian.delete").build());

        Role adminRole = roleService.save(Role.builder().roleName("ADMIN").build());
        Role userRole = roleService.save(Role.builder().roleName("USER").build());
        Role teacherRole = roleService.save(Role.builder().roleName("TEACHER").build());
        Role guardianRole = roleService.save(Role.builder().roleName("GUARDIAN").build());

        //Set.Of returns an immutable set, so new HashSet instantiates a mutable Set
        adminRole.setAuthorities(new HashSet<>(Set.of(createAdmin, updateAdmin, readAdmin, deleteAdmin,
                createUser, readUser, updateUser, deleteUser, createTeacher, readTeacher, updateTeacher, deleteTeacher,
                createGuardian, readGuardian, updateGuardian, deleteGuardian)));

        userRole.setAuthorities(new HashSet<>(Set.of(createUser, readUser, updateUser, deleteUser,
                createTeacher, readTeacher, updateTeacher, deleteTeacher,
                createGuardian, readGuardian, updateGuardian, deleteGuardian)));

        teacherRole.setAuthorities(new HashSet<>(Set.of(createTeacher, readTeacher, updateTeacher, deleteTeacher,
                createGuardian, readGuardian, updateGuardian, deleteGuardian)));

        guardianRole.setAuthorities(new HashSet<>(Set.of(createGuardian, readGuardian, updateGuardian, deleteGuardian)));

        roleService.save(adminRole);
        roleService.save(userRole);
        roleService.save(teacherRole);
        roleService.save(guardianRole);

        log.debug("Roles added: " + roleService.findAll().size());
        log.debug("Authorities added: " + authorityService.findAll().size());

        userService.save(User.builder()
                .username("admin")
                .password(passwordEncoder.encode("admin123"))
                .role(adminRole)
                .build());
        userService.save(User.builder()
                .username("user")
                .password(passwordEncoder.encode("user123"))
                .role(userRole)
                .build());
        userService.save(User.builder()
                .username("teacher")
                .password(passwordEncoder.encode("teacher123"))
                .role(teacherRole)
                .build());
        userService.save(User.builder()
                .username("guardian1")
                .password(passwordEncoder.encode("guardian123"))
                .role(guardianRole)
                .build());
        userService.save(User.builder()
                .username("guardian2")
                .password(passwordEncoder.encode("guardian456"))
                .role(guardianRole)
                .build());
        log.debug("Accounts added: " + userService.findAll().size());

        userService.findByUsername("admin").getAuthorities().forEach(authority ->
            System.out.println("Admin permission: " + authority.getAuthority()));
    }
}
