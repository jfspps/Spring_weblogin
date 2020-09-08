package com.springsecurity.weblogin.web.controllers;

import com.springsecurity.weblogin.model.security.*;
import com.springsecurity.weblogin.services.securityServices.*;
import com.springsecurity.weblogin.web.permissionAnnot.AdminCreate;
import com.springsecurity.weblogin.web.permissionAnnot.AdminRead;
import com.springsecurity.weblogin.web.permissionAnnot.GuardianRead;
import com.springsecurity.weblogin.web.permissionAnnot.TeacherRead;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
@Controller
public class UserController {

    private final UserService userService;
    private final TeacherUserService teacherUserService;
    private final RoleService roleService;
    private final GuardianUserService guardianUserService;
    private final AdminUserService adminUserService;
    private final PasswordEncoder passwordEncoder;

    //prevent the HTTP form POST from editing listed properties
    @InitBinder
    public void setAllowedFields(WebDataBinder dataBinder){
        dataBinder.setDisallowedFields("id");
    }

    @GetMapping({"/", "/welcome"})
    public String welcomePage(){
        return "welcome";
    }

    //this overrides the default Spring Security login page
    @GetMapping("/login")
    public String loginPage(){
        return "login";
    }

    //sets login-error to true and triggers login.html to display 'wrong user or password'
    @GetMapping("/login-error")
    public String loginError(Model model) {
        model.addAttribute("loginError", true);
        return "login";
    }

    @GuardianRead
    @GetMapping("/authenticated")
    public String userLogin(Model model) {
        User user = userService.findByUsername(getUsername());
        model.addAttribute("userID", user.getId());
        model.addAttribute("user", getUsername());
        return "authenticated";
    }

    @GuardianRead
    @GetMapping("/userPage")
    public String userPage(Model model) {
        User user = userService.findByUsername(getUsername());
        model.addAttribute("userID", user.getId());
        model.addAttribute("user", getUsername());
        return "userPage";
    }

    @AdminRead
    @GetMapping("/adminPage")
    public String adminPage(Model model) {
        Set<User> users = new HashSet<>(userService.findAll());
        model.addAttribute("usersFound", users);
        User user = userService.findByUsername(getUsername());
        model.addAttribute("userID", user.getId());
        model.addAttribute("user", getUsername());
        return "adminPage";
    }

    //this overrides the default GET logout page
    @GuardianRead
    @PostMapping("/logout")
    public String logoutPage(HttpServletRequest request, HttpServletResponse response){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication != null){
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        return "welcome";
    }

    //lists all users on userPage
    @TeacherRead
    @GetMapping("/listUsers")
    public String listUsers(Model model){
        Set<User> userSet = new HashSet<>();
        //userSet is never null if user has one of the above roles
        userSet.addAll(userService.findAll());
        model.addAttribute("usersFound", userSet);
        User currentUser = userService.findByUsername(getUsername());
        model.addAttribute("userID", currentUser.getId());
        return "userPage";
    }

    @AdminRead
    @GetMapping("/createTeacher")
    public String newTeacher(Model model){
        User user = User.builder().build();
        model.addAttribute("newUser", user);
        model.addAttribute("user", getUsername());
        TeacherUser teacherUser = TeacherUser.builder().build();
        model.addAttribute("newTeacher", teacherUser);
        return "teacherCreate";
    }

    @AdminCreate
    @PostMapping("/createTeacher")
    public String newTeacher(@Valid @ModelAttribute("newTeacher") TeacherUser newTeacherUser,
                             @Valid @ModelAttribute("newUser") User newUser){
        if (!newTeacherUser.getTeacherUserName().isBlank()
                || !newUser.getUsername().isBlank() || !newUser.getPassword().isBlank()){
            if (userService.findByUsername(newUser.getUsername()) == null){
                if (teacherUserService.findByTeacherUserName(newTeacherUser.getTeacherUserName()) == null){
                    newTeacherUser(newTeacherUser, newUser);
                } else {
                    log.debug("TeacherUser with name provided already exists");
                }
            } else {
                log.debug("TeacherUser with username provided already exists");
            }
        } else {
            log.debug("All fields must be completed");
        }
        return "redirect:/adminPage";
    }

    @AdminRead
    @GetMapping("/createAdmin")
    public String newAdmin(Model model){
        User user = User.builder().build();
        model.addAttribute("newUser", user);
        model.addAttribute("user", getUsername());
        AdminUser adminUser = AdminUser.builder().build();
        model.addAttribute("newAdmin", adminUser);
        return "adminCreate";
    }

    @AdminCreate
    @PostMapping("/createAdmin")
    public String newAdmin(@Valid @ModelAttribute("newAdmin") AdminUser newAdminUser,
                             @Valid @ModelAttribute("newUser") User newUser){
        if (!newAdminUser.getAdminUserName().isBlank()
                || !newUser.getUsername().isBlank() || !newUser.getPassword().isBlank()){
            if (userService.findByUsername(newUser.getUsername()) == null){
                if (adminUserService.findByAdminUserName(newAdminUser.getAdminUserName()) == null){
                    newAdminUser(newAdminUser, newUser);
                } else {
                    log.debug("AdminUser with name provided already exists");
                }
            } else {
                log.debug("AdminUser with username provided already exists");
            }
        } else {
            log.debug("All fields must be completed");
        }
        return "redirect:/adminPage";
    }

    @AdminRead
    @GetMapping("/createGuardian")
    public String newGuardian(Model model){
        User user = User.builder().build();
        model.addAttribute("newUser", user);
        model.addAttribute("user", getUsername());
        GuardianUser guardianUser = GuardianUser.builder().build();
        model.addAttribute("newGuardian", guardianUser);
        return "guardianCreate";
    }

    @AdminCreate
    @PostMapping("/createGuardian")
    public String newGuardian(@Valid @ModelAttribute("newGuardian") GuardianUser newGuardianUser,
                           @Valid @ModelAttribute("newUser") User newUser){
        if (!newGuardianUser.getGuardianUserName().isBlank()
                || !newUser.getUsername().isBlank() || !newUser.getPassword().isBlank()){
            if (userService.findByUsername(newUser.getUsername()) == null){
                if (guardianUserService.findByGuardianUserName(newGuardianUser.getGuardianUserName()) == null){
                    newGuardianUser(newGuardianUser, newUser);
                } else {
                    log.debug("GuardianUser with name provided already exists");
                }
            } else {
                log.debug("GuardianUser with username provided already exists");
            }
        } else {
            log.debug("All fields must be completed");
        }
        return "redirect:/adminPage";
    }

    private String getUsername(){
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails) {
            return ((UserDetails)principal).getUsername();
        } else {
            return principal.toString();
        }
    }

    //assume here that all parameters are not null and not already on the DB
    private User newTeacherUser(TeacherUser newTeacherUser, User newUser) {
        Role teacherRole = roleService.findByRoleName("TEACHER");
        TeacherUser savedTeacherUser = teacherUserService.save(
                TeacherUser.builder().teacherUserName(newTeacherUser.getTeacherUserName()).build());
        User savedUser = userService.save(User.builder().teacherUser(savedTeacherUser)
                .username(newUser.getUsername()).password(passwordEncoder.encode(newUser.getPassword()))
                .role(teacherRole).build());
        log.debug("New Teacher name: " + savedUser.getTeacherUser().getTeacherUserName() + " with username" +
                savedUser.getUsername() + " and ID: " + savedUser.getId() + " added");
        return savedUser;
    }

    private User newAdminUser(AdminUser newAdminUser, User newUser) {
        Role adminRole = roleService.findByRoleName("ADMIN");
        AdminUser savedAdminUser = adminUserService.save(
                AdminUser.builder().adminUserName(newAdminUser.getAdminUserName()).build());
        User savedUser = userService.save(User.builder().adminUser(savedAdminUser)
                .username(newUser.getUsername()).password(passwordEncoder.encode(newUser.getPassword()))
                .role(adminRole).build());
        log.debug("New Admin name: " + savedUser.getAdminUser().getAdminUserName() + " with username" +
                savedUser.getUsername() + " and ID: " + savedUser.getId() + " added");
        return savedUser;
    }

    private User newGuardianUser(GuardianUser newGuardianUser, User newUser) {
        Role guardianRole = roleService.findByRoleName("GUARDIAN");
        GuardianUser savedGuardianUser = guardianUserService.save(
                GuardianUser.builder().guardianUserName(newGuardianUser.getGuardianUserName()).build());
        User savedUser = userService.save(User.builder().guardianUser(savedGuardianUser)
                .username(newUser.getUsername()).password(passwordEncoder.encode(newUser.getPassword()))
                .role(guardianRole).build());
        log.debug("New Guardian name: " + savedUser.getGuardianUser().getGuardianUserName() + " with username" +
                savedUser.getUsername() + " and ID: " + savedUser.getId() + " added");
        return savedUser;
    }
}
