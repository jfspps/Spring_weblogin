package com.springsecurity.weblogin.bootstrap.security;

import com.springsecurity.weblogin.model.TestRecord;
import com.springsecurity.weblogin.model.security.*;
import com.springsecurity.weblogin.services.TestRecordService;
import com.springsecurity.weblogin.services.securityServices.*;
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
@Profile(value = {"dev", "SDjpa"})
public class DataLoader_SDjpa implements CommandLineRunner {

    private final UserService userService;
    private final AuthorityService authorityService;
    private final RoleService roleService;
    private final AdminUserService adminUserService;
    private final GuardianUserService guardianUserService;
    private final TeacherUserService teacherUserService;
    private final TestRecordService testRecordService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        log.debug("Users on file: " + userService.findAll().size());
        log.debug("Authorities on file: " + authorityService.findAll().size());
        log.debug("Roles on file: " + roleService.findAll().size());

        if (userService.findAll().size() == 0){
            loadSecurityData();
            log.debug("Users database finished populating");
            loadAdminUsers();
            loadGuardianUsers();
            loadTeacherUsers();
        } else
            log.debug("Users database already contains data; no changes made");

        loadTestRecord();
        log.debug("TestRecords loaded: " + testRecordService.findAll().size());
    }

    private void loadTestRecord() {
        testRecordService.createTestRecord("Test record 1", "paulsmith");
        testRecordService.createTestRecord("Test record 2", "alexsmith");
        testRecordService.createTestRecord("Test record 3", "alexsmith");
    }

    private void loadSecurityData(){
        // Privileges Admin > User > Teacher > Guardian
        // all permissions below are in relation to TestRecord CRUD ops
        // a separate set of permissions for each object type (in schools, assignment, report, exam score etc.) would be
        // needed in future (e.g. admin to view exam results would be 'admin.examScore.read' for example

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

        //each is initialised with the admin, teacher and guardian users below
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
                .username("guardian")
                .password(passwordEncoder.encode("guardian123"))
                .role(guardianRole)
                .build());
        log.debug("User accounts added: " + userService.findAll().size());
    }

    public void loadAdminUsers(){
        Role adminRole = roleService.findByRoleName("ADMIN");

        // Instantiating the admin users (this must be done after Users)
        // AdminUsers can store non-Security related fields (department, academic year etc.)
        AdminUser johnSmith = adminUserService.save(AdminUser.builder().adminUserName("John Smith").build());
        AdminUser amySmith = adminUserService.save(AdminUser.builder().adminUserName("Amy Smith").build());

        //passwords are not displayed on the schema...?
        User johnSmithUser = userService.save(User.builder().username("johnsmith")
                .password(passwordEncoder.encode("johnsmith123"))
                .adminUser(johnSmith)
                .role(adminRole).build());

        User amySmithUser = userService.save(User.builder().username("amysmith")
                .password(passwordEncoder.encode("amysmith123"))
                .adminUser(amySmith)
                .role(adminRole).build());

        log.debug("AdminUsers added: " + johnSmithUser.getUsername() + " " + amySmithUser.getUsername());
    }

    public void loadGuardianUsers(){
        Role guardianRole = roleService.findByRoleName("GUARDIAN");

        // Instantiating the admin users (this must be done after Users)
        GuardianUser paulSmith = guardianUserService.save(GuardianUser.builder().guardianUserName("Paul Smith").build());
        GuardianUser alexSmith = guardianUserService.save(GuardianUser.builder().guardianUserName("Alex Smith").build());

        //passwords are not displayed on the schema...?
        User paulSmithUser = userService.save(User.builder().username("paulsmith")
                .password(passwordEncoder.encode("paulsmith123"))
                .guardianUser(paulSmith)
                .role(guardianRole).build());
        //other GuardianUsers can be assigned to paulsmith, with the same roles

        User alexSmithUser = userService.save(User.builder().username("alexsmith")
                .password(passwordEncoder.encode("alexsmith123"))
                .guardianUser(alexSmith)
                .role(guardianRole).build());

        log.debug("GuardianUsers added: " + paulSmithUser.getUsername() + " " + alexSmithUser.getUsername());
    }

    public void loadTeacherUsers(){
        Role teacherRole = roleService.findByRoleName("TEACHER");

        // Instantiating the admin users (this must be done after Users)
        TeacherUser keithJones = teacherUserService.save(TeacherUser.builder().teacherUserName("Keith Jones").build());
        TeacherUser maryManning = teacherUserService.save(TeacherUser.builder().teacherUserName("Mary Manning").build());

        //passwords are not displayed on the schema...?
        User keithJonesUser = userService.save(User.builder().username("keithjones")
                .password(passwordEncoder.encode("keithjones123"))
                .teacherUser(keithJones)
                .role(teacherRole).build());

        User maryManningUser = userService.save(User.builder().username("marymanning")
                .password(passwordEncoder.encode("marymanning123"))
                .teacherUser(maryManning)
                .role(teacherRole).build());

        log.debug("TeacherUsers added: " + keithJonesUser.getUsername() + " " + maryManningUser.getUsername());
    }
}
