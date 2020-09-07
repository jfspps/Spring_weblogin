package com.springsecurity.weblogin.web.controllers;

import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.services.securityServices.UserService;
import com.springsecurity.weblogin.web.permissionAnnot.AdminRead;
import com.springsecurity.weblogin.web.permissionAnnot.GuardianRead;
import com.springsecurity.weblogin.web.permissionAnnot.TeacherRead;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

@Controller
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

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

    private String getUsername(){
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails) {
            return ((UserDetails)principal).getUsername();
        } else {
            return principal.toString();
        }
    }
}
