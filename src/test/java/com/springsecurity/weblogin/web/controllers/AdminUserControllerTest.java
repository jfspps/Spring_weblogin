package com.springsecurity.weblogin.web.controllers;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithUserDetails;

import javax.transaction.Transactional;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Slf4j
@Transactional
@SpringBootTest
public class AdminUserControllerTest extends UserControllerTest {

    // user and AdminUser CRUD tests ===============================================================================
    //context loads adminUsers, teacherUsers, followed by guardianUsers
    //IDs are [1,2], [3,4] and [5,6] respectively

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void getCreateAdmin(String username, String pwd) throws Exception {
        mockMvc.perform(get("/createAdmin").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("adminCreate"))
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("newUser"))
                .andExpect(model().attributeExists("newAdmin"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void getCreateAdmin_FAIL(String username, String pwd) throws Exception {
        mockMvc.perform(get("/createAdmin").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void postCreateAdmin(String username, String pwd) throws Exception {
        mockMvc.perform(post("/createAdmin").with(httpBasic(username, pwd)).with(csrf())
                .param("adminUserName", "Grace Peters")
                .param("username", "gracepeters")
                .param("password", "gracepeters123"))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/adminPage"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void postCreateAdmin_BlankFields(String username, String pwd) throws Exception {
        mockMvc.perform(post("/createAdmin").with(httpBasic(username, pwd)).with(csrf())
                .param("adminUserName", "")
                .param("username", "")
                .param("password", ""))
                .andExpect(status().is2xxSuccessful())
                .andExpect(view().name("adminCreate"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void postCreateAdmin_FAIL(String username, String pwd) throws Exception {
        mockMvc.perform(post("/createAdmin").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().isForbidden());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void getUpdateAdmin(String username, String pwd) throws Exception {
        mockMvc.perform(get("/updateAdmin/1").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("adminUpdate"))
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("currentUser"))
                .andExpect(model().attributeExists("currentAdminUser"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void getUpdateAdminNOTFOUND(String username, String pwd) throws Exception {
        mockMvc.perform(get("/updateAdmin/3").with(httpBasic(username, pwd)))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/adminPage"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void getUpdateAdmin_FAIL(String username, String pwd) throws Exception {
        mockMvc.perform(get("/updateAdmin/2").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void postUpdateAdmin(String username, String pwd) throws Exception {
        mockMvc.perform(post("/updateAdmin/1").with(httpBasic(username, pwd)).with(csrf())
                .param("adminUserName", "blablablabla")
                .param("username", "someoneNotOnFile"))
                .andExpect(status().is2xxSuccessful())
                .andExpect(view().name("adminUpdate"))
                .andExpect(model().attributeExists("AdminUserSaved"))
                .andExpect(model().attributeExists("currentUser"))
                .andExpect(model().attributeExists("currentAdminUser"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void postUpdateAdmin_UsernameBlank(String username, String pwd) throws Exception {
        mockMvc.perform(post("/updateAdmin/1").with(httpBasic(username, pwd)).with(csrf())
                .param("adminUserName", "blablablabla")
                .param("username", ""))
                .andExpect(status().is2xxSuccessful())
                .andExpect(view().name("adminUpdate"))
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("usernameError"))
                .andExpect(model().attributeExists("currentUser"))
                .andExpect(model().attributeExists("currentAdminUser"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void postUpdateAdmin_AdminUserNameBlank(String username, String pwd) throws Exception {
        mockMvc.perform(post("/updateAdmin/1").with(httpBasic(username, pwd)).with(csrf())
                .param("adminUserName", "")
                .param("username", "asduafajlkasjdjlk"))
                .andExpect(status().is2xxSuccessful())
                .andExpect(view().name("adminUpdate"))
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("adminUserNameError"))
                .andExpect(model().attributeExists("currentUser"))
                .andExpect(model().attributeExists("currentAdminUser"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void postUpdateAdmin_UserExists(String username, String pwd) throws Exception {
        mockMvc.perform(post("/updateAdmin/1").with(httpBasic(username, pwd)).with(csrf())
                .param("adminUserName", "fdsfdsfds")
                .param("username", "paulsmith"))
                .andExpect(status().is2xxSuccessful())
                .andExpect(view().name("adminUpdate"))
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("usernameExists"))
                .andExpect(model().attributeExists("currentUser"))
                .andExpect(model().attributeExists("currentAdminUser"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void postUpdateAdmin_AdminUserExists(String username, String pwd) throws Exception {
        mockMvc.perform(post("/updateAdmin/1").with(httpBasic(username, pwd)).with(csrf())
                .param("adminUserName", "Amy Smith")
                .param("username", "johnsmith"))
                .andExpect(status().is2xxSuccessful())
                .andExpect(view().name("adminUpdate"))
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("adminUserExists"))
                .andExpect(model().attributeExists("currentUser"))
                .andExpect(model().attributeExists("currentAdminUser"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void postUpdateAdminFAIL(String username, String pwd) throws Exception {
        mockMvc.perform(post("/updateAdmin/1").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().isForbidden());
    }

    //admin members of the context can't delete themselves
    @WithUserDetails("johnsmith")
    @Test
    void deleteOtherUser() throws Exception {
        mockMvc.perform(post("/deleteUser/2").with(csrf()))
                .andExpect(status().is2xxSuccessful())
                .andExpect(view().name("confirmDelete"))
                .andExpect(model().attributeExists("confirmDelete"))
                .andExpect(model().attributeExists("returnURL"))
                .andExpect(model().attributeExists("pageTitle"));
    }

    @WithUserDetails("johnsmith")
    @Test
    void deleteYourself() throws Exception {
        mockMvc.perform(post("/deleteUser/1").with(csrf()))
                .andExpect(status().is2xxSuccessful())
                .andExpect(view().name("confirmDelete"))
                .andExpect(model().attributeExists("deniedDelete"))
                .andExpect(model().attributeExists("returnURL"))
                .andExpect(model().attributeExists("pageTitle"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void deleteUserFAIL(String username, String pwd) throws Exception {
        mockMvc.perform(post("/deleteUser/2").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().isForbidden());
    }
}
