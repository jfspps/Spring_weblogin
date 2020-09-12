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
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
    @GetMapping("/logout")
    public String logoutPage(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        return "redirect:/welcome";
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
    public String postResetPassword(@PathVariable String userID) {
        if (userService.findById(Long.valueOf(userID)) != null) {
            User currentUser = userService.findById(Long.valueOf(userID));
            currentUser.setPassword(passwordEncoder.encode(currentUser.getUsername() + "123"));
            userService.save(currentUser);
            log.debug("Password was reset");
            return "redirect:/" + userTypePage(currentUser) + "/" + currentUser.getId();
        }
        log.debug("User with ID: " + userID + " not found");
        return "redirect:/adminPage";
    }

    @AdminUpdate
    @PostMapping("/changePassword/{userID}")
    public String postChangePassword(@PathVariable String userID, @Valid @ModelAttribute("currentUser") User passwordChangeUser) {
        if (userService.findById(Long.valueOf(userID)) != null) {
            if (!passwordChangeUser.getPassword().isBlank()) {
                User saved = changeUserPassword(Long.valueOf(userID), passwordChangeUser);
                return "redirect:/" + userTypePage(saved) + "/" + saved.getId();
            } else {
                User found = userService.findById(Long.valueOf(userID));
                log.debug("Blank passwords are not permitted");
                return "redirect:/" + userTypePage(found) + "/" + found.getId();
            }
        }
        log.debug("User with ID: " + userID + " not found");
        return "redirect:/adminPage";
    }

    @AdminDelete
    @PostMapping("/deleteUser/{userID}")
    public String postDeleteUser(@PathVariable String userID, Model model) {
        if (userService.findById(Long.valueOf(userID)) != null) {
            User currentUser = userService.findById(Long.valueOf(userID));
            if (Long.valueOf(userID).equals(userService.findByUsername(getUsername()).getId())) {
                log.debug("Cannot delete yourself");
                model.addAttribute("deniedDelete", "You are not permitted to delete your own account");
                model.addAttribute("returnURL", userTypePage(currentUser) + "/" + userID);
                model.addAttribute("pageTitle", "previous page");
            } else {
                if (userTypeDelete(currentUser, userID)) {
                    model.addAttribute("confirmDelete", "User with username \"" + currentUser.getUsername() + "\" successfully deleted");
                    model.addAttribute("returnURL", "adminPage");
                    model.addAttribute("pageTitle", "Admin page");
                } else {
                    model.addAttribute("deniedDelete", "User with username \"" + currentUser.getUsername() + "\" was not deleted");
                    model.addAttribute("returnURL", "updateAdmin/" + currentUser.getId());
                    model.addAttribute("pageTitle", "previous page");
                }
            }
            return "confirmDelete";
        }
        log.debug("User with ID: " + userID + " not found");
        return "redirect:/adminPage";
    }

    // Admin CRUD ops =======================================================================================

    @AdminRead
    @GetMapping("/createAdmin")
    public String getNewAdmin(Model model) {
        User user = User.builder().build();
        model.addAttribute("newUser", user);
        model.addAttribute("user", getUsername());
        AdminUser adminUser = AdminUser.builder().build();
        model.addAttribute("newAdmin", adminUser);
        return "adminCreate";
    }

    @AdminCreate
    @PostMapping("/createAdmin")
    public String postNewAdmin(@Valid @ModelAttribute("newAdmin") AdminUser newAdminUser,
                               BindingResult adminBindingResult, @Valid @ModelAttribute("newUser") User newUser,
                               BindingResult userBindingResult) {
        boolean checksOut = true;

        checksOut = passwordIsOK(userBindingResult, checksOut, newUser.getPassword(),
                "Password length must be >= 8 characters");

        checksOut = newUser_usernameIsOK(userBindingResult, checksOut, newUser.getUsername(),
                "User's username length must be >= 8 characters");

        checksOut = newUserType_nameIsOK(adminBindingResult, checksOut, newAdminUser.getAdminUserName(),
                "AdminUser's name length must be >= 8 characters");

        if (!checksOut) {
            return "adminCreate";
        }

        // At present, Weblogin saves new AdminUser and User concurrently (treated as one entity) since we require a User password.
        // Different AdminUsers associated with the same User would require more functionality not offered here.
        // We proceed here assuming that different AdminUsers can be associated with the same User.

        // New Users, with given Roles, are instantiated before AdminUsers. One AdminUser is associated with many Users.
        // All User usernames and hence Users are unique. Check that the new AdminUser is not registering with a User it is already
        // associated with
        User userFound;
        AdminUser adminUserFound;
        if (userService.findByUsername(newUser.getUsername()) != null) {
            //User is already on file
            userFound = userService.findByUsername(newUser.getUsername());
            if (adminUserService.findByAdminUserName(newAdminUser.getAdminUserName()) != null) {
                //AdminUser is also on file
                adminUserFound = adminUserService.findByAdminUserName(newAdminUser.getAdminUserName());
                if (adminUserFound.getUsers().stream().anyMatch(user ->
                        user.getUsername().equals(userFound.getUsername()))) {
                    //already registered/associated (only option is to change the AdminUserName
                    log.debug("AdminUser is already registered with the given User");
                    adminBindingResult.rejectValue("adminUserName", "exists",
                            "AdminUser provided is already registered with given User. Please change the AdminUser name.");
                    return "adminCreate";
                }
                //not currently registered with given User (can save current form data)
            }
            //AdminUser not found (can save current form data)
        }
        //User not found (can save current form data)

        //all checks complete
        newAdminUser(newAdminUser, newUser);
        return "redirect:/adminPage";
    }

    @AdminUpdate
    @GetMapping("/updateAdmin/{adminUserID}")
    public String getUpdateAdmin(Model model, @PathVariable String adminUserID) {
        if (userService.findById(Long.valueOf(adminUserID)) == null) {
            log.debug("User with ID " + adminUserID + " not found");
            throw new NotFoundException();
        }
        User user = userService.findById(Long.valueOf(adminUserID));
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

    @AdminUpdate
    @PostMapping("/updateAdmin/{adminUserID}")
    public String postUpdateAdmin(@PathVariable String adminUserID, @Valid @ModelAttribute("currentUser") User currentUser,
                                  @Valid @ModelAttribute("currentAdminUser") AdminUser currentAdminUser) {
        User user = userService.findById(Long.valueOf(adminUserID));
        if (currentUser.getUsername() != null && currentAdminUser.getAdminUserName() != null) {
            user.setUsername(currentUser.getUsername());
            user.getAdminUser().setAdminUserName(currentAdminUser.getAdminUserName());
        } else {
            log.debug("Username and AdminUserName not recognised. No changes made");
            return "redirect:/updateAdmin/" + adminUserID;
        }
        User saved = userService.save(user);
        log.debug("Username: " + saved.getUsername() + ", adminUser name: " + saved.getAdminUser().getAdminUserName() +
                " saved");
        return "redirect:/updateAdmin/" + saved.getId();
    }

    // Teacher CRUD ops =======================================================================================

    @AdminRead
    @GetMapping("/createTeacher")
    public String getNewTeacher(Model model) {
        User user = User.builder().build();
        model.addAttribute("newUser", user);
        model.addAttribute("user", getUsername());
        TeacherUser teacherUser = TeacherUser.builder().build();
        model.addAttribute("newTeacher", teacherUser);
        return "teacherCreate";
    }

    //see postNewAdmin for comments
    @AdminCreate
    @PostMapping("/createTeacher")
    public String postNewTeacher(@Valid @ModelAttribute("newTeacher") TeacherUser newTeacherUser,
                                 BindingResult teacherBindingResult, @Valid @ModelAttribute("newUser") User newUser,
                                 BindingResult userBindingResult) {
        boolean checksOut = true;

        checksOut = passwordIsOK(userBindingResult, checksOut, newUser.getPassword(),
                "Password length must be >= 8 characters");

        checksOut = newUser_usernameIsOK(userBindingResult, checksOut, newUser.getUsername(),
                "User's username length must be >= 8 characters");

        checksOut = newUserType_nameIsOK(teacherBindingResult, checksOut, newTeacherUser.getTeacherUserName(),
                "TeacherUser's name length must be >= 8 characters");

        if (!checksOut) {
            return "teacherCreate";
        }

        User userFound;
        TeacherUser teacherUserFound;
        if (userService.findByUsername(newUser.getUsername()) != null) {
            userFound = userService.findByUsername(newUser.getUsername());
            if (teacherUserService.findByTeacherUserName(newTeacherUser.getTeacherUserName()) != null) {
                teacherUserFound = teacherUserService.findByTeacherUserName(newTeacherUser.getTeacherUserName());
                if (teacherUserFound.getUsers().stream().anyMatch(user ->
                        user.getUsername().equals(userFound.getUsername()))) {
                    log.debug("TeacherUser is already registered with the given User");
                    teacherBindingResult.rejectValue("teacherUserName", "exists",
                            "TeacherUser provided is already registered with given User. Please change the TeacherUser name.");
                    return "teacherCreate";
                }
            }
        }

        newTeacherUser(newTeacherUser, newUser);
        return "redirect:/adminPage";
    }

    @AdminUpdate
    @GetMapping("/updateTeacher/{teacherUserID}")
    public String getUpdateTeacher(Model model, @PathVariable String teacherUserID) {
        if (userService.findById(Long.valueOf(teacherUserID)) == null) {
            log.debug("User with ID " + teacherUserID + " not found");
            throw new NotFoundException();
        }
        User user = userService.findById(Long.valueOf(teacherUserID));
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

    @AdminUpdate
    @PostMapping("/updateTeacher/{teacherUserID}")
    public String postUpdateTeacher(@PathVariable String teacherUserID, @Valid @ModelAttribute("currentUser") User currentUser,
                                    @Valid @ModelAttribute("currentTeacherUser") TeacherUser currentTeacherUser) {
        User user = userService.findById(Long.valueOf(teacherUserID));
        if (currentUser.getUsername() != null && currentTeacherUser.getTeacherUserName() != null) {
            user.setUsername(currentUser.getUsername());
            user.getTeacherUser().setTeacherUserName(currentTeacherUser.getTeacherUserName());
        } else {
            log.debug("Username and TeacherUserName not recognised. No changes made");
            return "redirect:/updateTeacher/" + teacherUserID;
        }
        User saved = userService.save(user);
        log.debug("Username: " + saved.getUsername() + ", teacherUser name: " + saved.getTeacherUser().getTeacherUserName() +
                " saved");
        return "redirect:/updateTeacher/" + saved.getId();
    }

    // Guardian CRUD ops =======================================================================================

    @AdminRead
    @GetMapping("/createGuardian")
    public String getNewGuardian(Model model) {
        User user = User.builder().build();
        model.addAttribute("newUser", user);
        model.addAttribute("user", getUsername());
        GuardianUser guardianUser = GuardianUser.builder().build();
        model.addAttribute("newGuardian", guardianUser);
        return "guardianCreate";
    }

    //see postNewAdmin for comments
    @AdminCreate
    @PostMapping("/createGuardian")
    public String postNewGuardian(@Valid @ModelAttribute("newGuardian") GuardianUser newGuardianUser,
                                  BindingResult guardianBindingResult, @Valid @ModelAttribute("newUser") User newUser,
                                  BindingResult userBindingResult) {
        boolean checksOut = true;

        checksOut = passwordIsOK(userBindingResult, checksOut, newUser.getPassword(),
                "Password length must be >= 8 characters");

        checksOut = newUser_usernameIsOK(userBindingResult, checksOut, newUser.getUsername(),
                "User's username length must be >= 8 characters");

        checksOut = newUserType_nameIsOK(guardianBindingResult, checksOut, newGuardianUser.getGuardianUserName(),
                "GuardianUser's name length must be >= 8 characters");

        if (!checksOut) {
            return "guardianCreate";
        }

        User userFound;
        GuardianUser guardianUserFound;
        if (userService.findByUsername(newUser.getUsername()) != null) {
            userFound = userService.findByUsername(newUser.getUsername());
            if (guardianUserService.findByGuardianUserName(newGuardianUser.getGuardianUserName()) != null) {
                guardianUserFound = guardianUserService.findByGuardianUserName(newGuardianUser.getGuardianUserName());
                if (guardianUserFound.getUsers().stream().anyMatch(user ->
                        user.getUsername().equals(userFound.getUsername()))) {
                    log.debug("GuardianUser is already registered with the given User");
                    guardianBindingResult.rejectValue("guardianUserName", "exists",
                            "GuardianUser provided is already registered with given User. Please change the GuardianUser name.");
                    return "guardianCreate";
                }
            }
        }

        newGuardianUser(newGuardianUser, newUser);
        return "redirect:/adminPage";
    }

    @AdminUpdate
    @GetMapping("/updateGuardian/{guardianUserID}")
    public String getUpdateGuardian(Model model, @PathVariable String guardianUserID) {
        if (userService.findById(Long.valueOf(guardianUserID)) == null) {
            log.debug("User with ID " + guardianUserID + " not found");
            throw new NotFoundException();
        }
        User user = userService.findById(Long.valueOf(guardianUserID));
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

    @AdminUpdate
    @PostMapping("/updateGuardian/{guardianUserID}")
    public String postUpdateTeacher(@PathVariable String guardianUserID, @Valid @ModelAttribute("currentUser") User currentUser,
                                    @Valid @ModelAttribute("currentGuardianUser") GuardianUser currentGuardianUser) {
        User user = userService.findById(Long.valueOf(guardianUserID));
        if (currentUser.getUsername() != null && currentGuardianUser.getGuardianUserName() != null) {
            user.setUsername(currentUser.getUsername());
            user.getGuardianUser().setGuardianUserName(currentGuardianUser.getGuardianUserName());
        } else {
            log.debug("Username and GuardianUserName not recognised. No changes made");
            return "redirect:/updateGuardian/" + guardianUserID;
        }
        User saved = userService.save(user);
        log.debug("Username: " + saved.getUsername() + ", guardianUser name: " + saved.getGuardianUser().getGuardianUserName() +
                " saved");
        return "redirect:/updateGuardian/" + saved.getId();
    }

    // end of CRUD ops ==========================================================================================
    //the following methods are called by the above controller methods only if the required parameters are verified

    /**inserts URL path related Strings dependent on the Usertype (AdminUser, TeacherUser or GuardianUser)*/
    @AdminRead
    private String userTypePage(User user) {
        if (user.getAdminUser() != null) {
            return "updateAdmin";
        } else if (user.getTeacherUser() != null) {
            return "updateTeacher";
        } else
            return "updateGuardian";
    }

    /**executes JPA User delete() dependent on the Usertype (AdminUser, TeacherUser or GuardianUser)*/
    @AdminDelete
    private boolean userTypeDelete(User user, String userID) {
        if (user.getAdminUser() != null) {
            deleteAdminUser(user.getId());
        } else if (user.getTeacherUser() != null) {
            deleteTeacherUser(user.getId());
        } else
            deleteGuardianUser(user.getId());
        if (userService.findById(Long.valueOf(userID)) != null) {
            log.debug("User with ID: " + userID + " was not deleted");
            return false;
        } else
            return true;
    }

    @AdminRead
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

    /**Checks if a AdminUser/TeacherUser/GuardianUser name property is valid*/
    @AdminCreate
    private boolean newUserType_nameIsOK(BindingResult adminBindingResult, boolean checksOut, String adminUserName, String s) {
        if (adminUserName == null || adminUserName.length() < 8) {
            log.debug(s);
//            adminBindingResult.getAllErrors().forEach(objectError -> {
//                log.debug(objectError.toString());
//            });
            checksOut = false;
        }
        return checksOut;
    }

    /**Checks if a User username property is valid*/
    @AdminCreate
    private boolean newUser_usernameIsOK(BindingResult userBindingResult, boolean checksOut, String username, String s) {
        if (username == null || username.length() < 8) {
            //if the User username needs attention
            log.debug(s);
//            userBindingResult.getAllErrors().forEach(objectError -> {
//                log.debug(objectError.toString());
//            });
            checksOut = false;
        }
        return checksOut;
    }

    @AdminUpdate
    private boolean passwordIsOK(BindingResult userBindingResult, boolean checksOut, String password, String s) {
        if (password == null || password.length() < 8) {
            //if the password needs attention
            log.debug(s);
//            userBindingResult.getAllErrors().forEach(objectError -> {
//                log.debug(objectError.toString());
//            });
            checksOut = false;
        }
        return checksOut;
    }

    //assume here that all parameters are not null and not already on the DB
    @AdminUpdate
    private void newTeacherUser(TeacherUser newTeacherUser, User newUser) {
        Role teacherRole = roleService.findByRoleName("TEACHER");
        TeacherUser savedTeacherUser = teacherUserService.save(
                TeacherUser.builder().teacherUserName(newTeacherUser.getTeacherUserName()).build());
        User savedUser = userService.save(User.builder().teacherUser(savedTeacherUser)
                .username(newUser.getUsername()).password(passwordEncoder.encode(newUser.getPassword()))
                .role(teacherRole).build());
        log.debug("New Teacher name: " + savedUser.getTeacherUser().getTeacherUserName() + " with username" +
                savedUser.getUsername() + " and ID: " + savedUser.getId() + " added");
    }

    @AdminUpdate
    private void newAdminUser(AdminUser newAdminUser, User newUser) {
        Role adminRole = roleService.findByRoleName("ADMIN");
        AdminUser savedAdminUser = adminUserService.save(
                AdminUser.builder().adminUserName(newAdminUser.getAdminUserName()).build());
        User savedUser = userService.save(User.builder().adminUser(savedAdminUser)
                .username(newUser.getUsername()).password(passwordEncoder.encode(newUser.getPassword()))
                .role(adminRole).build());
        log.debug("New Admin name: " + savedUser.getAdminUser().getAdminUserName() + " with username" +
                savedUser.getUsername() + " and ID: " + savedUser.getId() + " added");
    }

    @AdminUpdate
    private void newGuardianUser(GuardianUser newGuardianUser, User newUser) {
        Role guardianRole = roleService.findByRoleName("GUARDIAN");
        GuardianUser savedGuardianUser = guardianUserService.save(
                GuardianUser.builder().guardianUserName(newGuardianUser.getGuardianUserName()).build());
        User savedUser = userService.save(User.builder().guardianUser(savedGuardianUser)
                .username(newUser.getUsername()).password(passwordEncoder.encode(newUser.getPassword()))
                .role(guardianRole).build());
        log.debug("New Guardian name: " + savedUser.getGuardianUser().getGuardianUserName() + " with username" +
                savedUser.getUsername() + " and ID: " + savedUser.getId() + " added");
    }

    @AdminDelete
    private void deleteAdminUser(Long userID) {
        //AdminUser to User is ManyToOne; do not delete AdminUser unless size == 0
        User toBeDeleted = userService.findById(userID);
        AdminUser adminUser = toBeDeleted.getAdminUser();

        //settle the mappings between User and AdminUser
        toBeDeleted.setAdminUser(null);
        adminUser.getUsers().removeIf(user -> user.getUsername().equals(toBeDeleted.getUsername()));
        adminUserService.save(adminUser);

        String adminUserName = adminUser.getAdminUserName();
        Long adminUserId = adminUser.getId();
        if (adminUser.getUsers().isEmpty()) {
            adminUserService.deleteById(adminUserId);
            log.debug("AdminUser, " + adminUserName + ", User set is now empty and has been deleted");
        } else {
            log.debug("AdminUser, " + adminUserName + ", has " + adminUser.getUsers().size() + " remaining Users associated");
        }

        userService.deleteById(userID);
    }

    @AdminDelete
    private void deleteTeacherUser(Long userID) {
        //TeacherUser to User is ManyToOne; do not delete TeacherUser unless size == 0
        User toBeDeleted = userService.findById(userID);
        TeacherUser teacherUser = toBeDeleted.getTeacherUser();

        //settle the mappings between User and TeacherUser
        toBeDeleted.setTeacherUser(null);
        teacherUser.getUsers().removeIf(user -> user.getUsername().equals(toBeDeleted.getUsername()));
        teacherUserService.save(teacherUser);

        String teacherUserName = teacherUser.getTeacherUserName();
        Long teacherUserId = teacherUser.getId();
        if (teacherUser.getUsers().isEmpty()) {
            teacherUserService.deleteById(teacherUserId);
            log.debug("TeacherUser, " + teacherUserName + ", User set is now empty and has been deleted");
        } else {
            log.debug("TeacherUser, " + teacherUserName + ", has " + teacherUser.getUsers().size() + " remaining Users associated");
        }

        userService.deleteById(userID);
    }

    @AdminDelete
    private void deleteGuardianUser(Long userID) {
        //GuardianUser to User is ManyToOne; do not delete AdminUser unless size == 0
        User toBeDeleted = userService.findById(userID);
        GuardianUser guardianUser = toBeDeleted.getGuardianUser();

        //settle the mappings between User and AdminUser
        toBeDeleted.setGuardianUser(null);
        guardianUser.getUsers().removeIf(user -> user.getUsername().equals(toBeDeleted.getUsername()));
        guardianUserService.save(guardianUser);

        String guardianUserName = guardianUser.getGuardianUserName();
        Long guardianUserId = guardianUser.getId();
        if (guardianUser.getUsers().isEmpty()) {
            guardianUserService.deleteById(guardianUserId);
            log.debug("GuardianUser, " + guardianUserName + ", User set is now empty and has been deleted");
        } else {
            log.debug("GuardianUser, " + guardianUserName + ", has " + guardianUser.getUsers().size() + " remaining Users associated");
        }

        userService.deleteById(userID);
    }
}
