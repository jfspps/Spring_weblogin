package com.springsecurity.weblogin.web.controllers;

import com.springsecurity.weblogin.exceptions.NotFoundException;
import com.springsecurity.weblogin.model.security.*;
import com.springsecurity.weblogin.services.securityServices.*;
import com.springsecurity.weblogin.web.permissionAnnot.*;
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
import javax.transaction.Transactional;
import javax.validation.Valid;
import java.util.*;
import java.util.stream.Collectors;

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
    public void setAllowedFields(WebDataBinder dataBinder) {
        dataBinder.setDisallowedFields("id");
    }

    @GetMapping({"/", "/welcome"})
    public String welcomePage() {
        return "welcome";
    }

    //this overrides the default Spring Security login page
    @GetMapping("/login")
    public String loginPage() {
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
        Set<User> AdminUsers = userService.findAll().stream().filter(
                user -> user.getAdminUser() != null
        ).collect(Collectors.toSet());
        model.addAttribute("AdminUsersFound", AdminUsers);

        Set<User> TeacherUsers = userService.findAll().stream().filter(
                user -> user.getTeacherUser() != null
        ).collect(Collectors.toSet());
        model.addAttribute("TeacherUsersFound", TeacherUsers);

        Set<User> GuardianUsers = userService.findAll().stream().filter(
                user -> user.getGuardianUser() != null
        ).collect(Collectors.toSet());
        model.addAttribute("GuardianUsersFound", GuardianUsers);

        //current authenticated user details
        User user = userService.findByUsername(getUsername());
        model.addAttribute("userID", user.getId());
        model.addAttribute("user", getUsername());
        return "adminPage";
    }

    //this overrides the default GET logout page
    @GuardianRead
    @PostMapping("/logout")
    public String logoutPage(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        return "welcome";
    }

    //lists all users on userPage
    @TeacherRead
    @GetMapping("/listUsers")
    public String listUsers(Model model) {
        Set<User> userSet = new HashSet<>();
        //userSet is never null if user has one of the above roles
        userSet.addAll(userService.findAll());
        model.addAttribute("usersFound", userSet);
        User currentUser = userService.findByUsername(getUsername());
        model.addAttribute("userID", currentUser.getId());
        return "userPage";
    }

    @AdminUpdate
    @PostMapping("/resetPassword/{userID}")
    public String postResetPassword(@PathVariable Long userID) {
        if (userService.findById(userID) != null) {
            User currentUser = userService.findById(userID);
            currentUser.setPassword(passwordEncoder.encode(currentUser.getUsername() + "123"));
            userService.save(currentUser);
            log.debug("Password was reset");
            if (currentUser.getAdminUser() != null) {
                return "redirect:/updateAdmin/" + currentUser.getId();
            } else if (currentUser.getTeacherUser() != null) {
                return "redirect:/updateTeacher/" + currentUser.getId();
            } else {
                return "redirect:/updateGuardian/" + currentUser.getId();
            }
        }
        log.debug("Unauthorised password reset requested");
        return "redirect:/logout";
    }

    @AdminUpdate
    @PostMapping("/changePassword/{userID}")
    public String postChangePassword(@PathVariable Long userID, @Valid @ModelAttribute("currentUser") User passwordChangeUser) {
        if (userService.findById(userID) != null) {
            if (!passwordChangeUser.getPassword().isBlank()){
                User saved = changeUserPassword(userID, passwordChangeUser);
                if (saved.getAdminUser() != null) {
                    return "redirect:/updateAdmin/" + saved.getId();
                } else if (saved.getTeacherUser() != null) {
                    return "redirect:/updateTeacher/" + saved.getId();
                } else {
                    return "redirect:/updateGuardian/" + saved.getId();
                }
            } else {
                User found = userService.findById(userID);
                log.debug("Blank passwords are not permitted");
                if (found.getAdminUser() != null) {
                    return "redirect:/updateAdmin/" + found.getId();
                } else if (found.getTeacherUser() != null) {
                    return "redirect:/updateTeacher/" + found.getId();
                } else {
                    return "redirect:/updateGuardian/" + found.getId();
                }
            }
        }
        log.debug("Unauthorised password reset requested");
        return "redirect:/adminPage";
    }

    // Admin CRUD ops =======================================================================================

    @AdminRead
    @GetMapping("/createAdmin")
    public String newAdmin(Model model) {
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
                           @Valid @ModelAttribute("newUser") User newUser) {
        if (newAdminUser.getAdminUserName() != null
                || newUser.getUsername() != null || newUser.getPassword() != null) {
            if (userService.findByUsername(newUser.getUsername()) == null) {
                if (adminUserService.findByAdminUserName(newAdminUser.getAdminUserName()) == null) {
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

    @AdminUpdate
    @GetMapping("/updateAdmin/{adminUserID}")
    public String updateAdmin(Model model, @PathVariable Long adminUserID) {
        User user = userService.findById(adminUserID);
        //guard against wrong adminUser by user ID
        if (user.getAdminUser() == null) {
            log.debug("No adminUser associated with given user");
            return "redirect:/adminPage";
        } else {
            AdminUser adminUser = user.getAdminUser();
            model.addAttribute("user", getUsername());
            model.addAttribute("currentUser", user);
            model.addAttribute("currentAdminUser", adminUser);
            return "adminUpdate";
        }
    }

    // Teacher CRUD ops =======================================================================================

    @AdminRead
    @GetMapping("/createTeacher")
    public String newTeacher(Model model) {
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
                             @Valid @ModelAttribute("newUser") User newUser) {
        if (newTeacherUser.getTeacherUserName() != null
                || newUser.getUsername() != null || newUser.getPassword() != null) {
            if (userService.findByUsername(newUser.getUsername()) == null) {
                if (teacherUserService.findByTeacherUserName(newTeacherUser.getTeacherUserName()) == null) {
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

    @AdminUpdate
    @GetMapping("/updateTeacher/{teacherUserID}")
    public String updateTeacher(Model model, @PathVariable Long teacherUserID) {
        User user = userService.findById(teacherUserID);
        if (user.getTeacherUser() == null) {
            log.debug("No teacherUser associated with given user");
            return "redirect:/adminPage";
        } else {
            TeacherUser teacherUser = user.getTeacherUser();
            model.addAttribute("user", getUsername());
            model.addAttribute("currentUser", user);
            model.addAttribute("currentTeacherUser", teacherUser);
            return "teacherUpdate";
        }
    }

    // Guardian CRUD ops =======================================================================================

    @AdminRead
    @GetMapping("/createGuardian")
    public String newGuardian(Model model) {
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
                              @Valid @ModelAttribute("newUser") User newUser) {
        if (newGuardianUser.getGuardianUserName() != null
                || newUser.getUsername() != null || newUser.getPassword() != null) {
            if (userService.findByUsername(newUser.getUsername()) == null) {
                if (guardianUserService.findByGuardianUserName(newGuardianUser.getGuardianUserName()) == null) {
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

    @AdminUpdate
    @GetMapping("/updateGuardian/{guardianUserID}")
    public String updateGuardian(Model model, @PathVariable Long guardianUserID) {
        User user = userService.findById(guardianUserID);
        if (user.getGuardianUser() == null) {
            log.debug("No guardianUser associated with given user");
            return "redirect:/adminPage";
        } else {
            GuardianUser guardianUser = user.getGuardianUser();
            model.addAttribute("user", getUsername());
            model.addAttribute("currentUser", user);
            model.addAttribute("currentGuardianUser", guardianUser);
            return "guardianUpdate";
        }
    }

    // end of CRUD ops ==========================================================================================

    @AdminUpdate
    private String getUsername() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails) {
            return ((UserDetails) principal).getUsername();
        } else {
            return principal.toString();
        }
    }

    @AdminUpdate
    private User changeUserPassword(Long userID, User userOnFile) {
        User found = userService.findById(userID);
        found.setPassword(passwordEncoder.encode(userOnFile.getPassword()));
        User saved = userService.save(found);
        log.debug("Password change for " + saved.getUsername() + " has been saved");
        return saved;
    }

    //assume here that all parameters are not null and not already on the DB
    @AdminUpdate
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

    @AdminUpdate
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

    @AdminUpdate
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
