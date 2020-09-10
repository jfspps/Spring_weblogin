package com.springsecurity.weblogin.web.controllers;

import com.springsecurity.weblogin.model.security.AdminUser;
import com.springsecurity.weblogin.model.security.GuardianUser;
import com.springsecurity.weblogin.model.security.TeacherUser;
import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.services.securityServices.AdminUserService;
import com.springsecurity.weblogin.services.securityServices.GuardianUserService;
import com.springsecurity.weblogin.services.securityServices.TeacherUserService;
import com.springsecurity.weblogin.services.securityServices.UserService;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import javax.transaction.Transactional;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

//USER <--> ROLE <--> AUTHORITY

// Cross-site request forgery, also known as session riding (sometimes pronounced sea-surf) or XSRF, is a type of
// malicious exploit of a website where unauthorized commands are submitted from a user that the web application trusts.
// POST requests, with csrf enabled, will be denied (HTTP 403) in the browser but likely pass in Spring MVC tests
// (tests bypass Spring security); if POST fails in the browser, add:
// <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}" />
// in the given form where other <input> tags are declared (the above token is added with the requisite info to the server)

// more info here: https://portswigger.net/web-security/csrf/tokens

@Slf4j
@Transactional
@SpringBootTest
//substitute @WebMvcTest for @SpringBootTest to guarantee tests capture all Spring Boot dependencies which were loaded at the time
class UserControllerTest extends SecurityCredentialsTest {

    @Mock
    UserService userServiceTEST;

    @Mock
    AdminUserService adminUserServiceTEST;

    @Mock
    TeacherUserService teacherUserServiceTEST;

    @Mock
    GuardianUserService guardianUserServiceTEST;

    @WithAnonymousUser
    @Test
    void welcomePage() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(view().name("welcome"));
    }

    //this fails with Spring Security with any username ('random' is effectively replaced with anyString())
    @WithMockUser("random")
    @Test
    void loginPage_random() throws Exception {
        mockMvc.perform(get("/authenticated"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    void loginAuthHttpBasicFAIL() throws Exception {
        MvcResult unauthenticatedResult = mockMvc.perform(get("/authenticated").with(httpBasic("randomPerson", "xyz")))
                .andExpect(status().isUnauthorized())
                .andReturn();

        //not printing anything it seems...
        System.out.println("loginAuthHttpBasicFAIL(), redirected URL: " + unauthenticatedResult.getResponse().getContentAsString());
    }

    @Test
    void logoutPage() throws Exception {
        mockMvc.perform(post("/logout").with(csrf()))
                .andExpect(status().is2xxSuccessful());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllUsers")
    @ParameterizedTest
    void redirectToLoginWhenRequestingAuthenticated_AllUsers(String username, String pwd) throws Exception {
        //see https://www.baeldung.com/spring-security-redirect-login

        MockHttpServletRequestBuilder securedResourceAccess = get("/authenticated");

        //gather what happens when accessing /authenticated as an anonymous user
        MvcResult unauthenticatedResult = mockMvc
                .perform(securedResourceAccess)
                .andExpect(status().is4xxClientError())
                .andReturn();

        //retrieve any session data
        MockHttpSession session = (MockHttpSession) unauthenticatedResult
                .getRequest()
                .getSession();

        //post login data under same session
        mockMvc
                .perform(post("/login")
                        .param("username", username)
                        .param("password", pwd)
                        .session(session)
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/authenticated"))
                .andReturn();

        //verify that the user session enables future access without re-logging in
        mockMvc
                .perform(securedResourceAccess.session(session))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("userID"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllUsers")
    @ParameterizedTest
    void redirectToLoginWhenRequestingUserPage_AllUsers(String username, String pwd) throws Exception {
        //see https://www.baeldung.com/spring-security-redirect-login

        MockHttpServletRequestBuilder securedResourceAccess = get("/userPage");

        //gather what happens when accessing /authenticated as an anonymous user
        MvcResult unauthenticatedResult = mockMvc
                .perform(securedResourceAccess)
                .andExpect(status().is4xxClientError())
                .andReturn();

        //retrieve any session data
        MockHttpSession session = (MockHttpSession) unauthenticatedResult
                .getRequest()
                .getSession();

        //post login data under same session
        mockMvc
                .perform(post("/login")
                        .param("username", username)
                        .param("password", pwd)
                        .session(session)
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/userPage"))
                .andReturn();

        //verify that the user session enables future access without re-logging in
        mockMvc
                .perform(securedResourceAccess.session(session))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("userID"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllUsers")
    @ParameterizedTest
    void loginAuthHttpBasic_AllUsers_Authenticated(String username, String pwd) throws Exception {
        mockMvc.perform(get("/authenticated").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("authenticated"))
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("userID"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllUsers")
    @ParameterizedTest
    void loginAuthHttpBasic_AllUsers_UserPage(String username, String pwd) throws Exception {
        mockMvc.perform(get("/userPage").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("userPage"))
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("userID"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolStaff")
    @ParameterizedTest
    void listUser_SchoolStaff_PASS(String username, String pwd) throws Exception{
        mockMvc.perform(get("/listUsers").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("userPage"))
                .andExpect(model().attributeExists("usersFound"))
                .andExpect(model().attributeExists("userID"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllGuardians")
    @ParameterizedTest
    void listUser_Guardians_FAIL(String username, String pwd) throws Exception{
        mockMvc.perform(get("/listUsers").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void adminPagePASS_withAdmin(String username, String pwd) throws Exception {
        mockMvc.perform(get("/adminPage").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("adminPage"))
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("userID"))
                .andExpect(model().attributeExists("GuardianUsersFound"))
                .andExpect(model().attributeExists("AdminUsersFound"))
                .andExpect(model().attributeExists("TeacherUsersFound"));
    }

    //same test as above with new annotation (username and pwd are pulled from JPAUserDetails)
    @Test
    @WithUserDetails("johnsmith")
    void adminPagePASS_withAdmin_withoutHttpBasic() throws Exception {
        mockMvc.perform(get("/adminPage"))
                .andExpect(status().isOk())
                .andExpect(view().name("adminPage"))
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("userID"))
                .andExpect(model().attributeExists("GuardianUsersFound"))
                .andExpect(model().attributeExists("AdminUsersFound"))
                .andExpect(model().attributeExists("TeacherUsersFound"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void adminPageFAIL_withNonAdmin(String username, String pwd) throws Exception {
        mockMvc.perform(get("/adminPage").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void postResetPassword_ADMIN(String username, String pwd) throws Exception {
        mockMvc.perform(post("/resetPassword/1").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/updateAdmin/1"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void postResetPassword_TEACHER(String username, String pwd) throws Exception {
        mockMvc.perform(post("/resetPassword/3").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/updateTeacher/3"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void postResetPassword_GUARDIAN(String username, String pwd) throws Exception {
        mockMvc.perform(post("/resetPassword/5").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/updateGuardian/5"));
    }

    //todo: test postChangePassword

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void postChangePassword_outOfBounds(String username, String pwd) throws Exception {
        mockMvc.perform(post("/changePassword/5000").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/adminPage"));
    }

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
        mockMvc.perform(post("/createAdmin").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/adminPage"));
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
        mockMvc.perform(post("/updateAdmin/1").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/updateAdmin/1"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void postUpdateAdminFAIL(String username, String pwd) throws Exception {
        mockMvc.perform(post("/updateAdmin/1").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().isForbidden());
    }

    // user and TeacherUser CRUD tests ===============================================================================
    //context loads adminUsers, teacherUsers, followed by guardianUsers
    //IDs are [1,2], [3,4] and [5,6] respectively

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void getCreateTeacher(String username, String pwd) throws Exception {
        mockMvc.perform(get("/createTeacher").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("teacherCreate"))
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("newUser"))
                .andExpect(model().attributeExists("newTeacher"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void getCreateTeacher_FAIL(String username, String pwd) throws Exception {
        mockMvc.perform(get("/createTeacher").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void postCreateTeacher(String username, String pwd) throws Exception {
        mockMvc.perform(post("/createTeacher").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/adminPage"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void postCreateTeacher_FAIL(String username, String pwd) throws Exception {
        mockMvc.perform(post("/createTeacher").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().isForbidden());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void getUpdateTeacher(String username, String pwd) throws Exception {
        mockMvc.perform(get("/updateTeacher/4").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("teacherUpdate"))
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("currentTeacherUser"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void getUpdateTeacherNOTFOUND(String username, String pwd) throws Exception {
        mockMvc.perform(get("/updateTeacher/5").with(httpBasic(username, pwd)))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/adminPage"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void getUpdateTeacher_FAIL(String username, String pwd) throws Exception {
        mockMvc.perform(get("/updateTeacher/3").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void postUpdateTeacher(String username, String pwd) throws Exception {
        mockMvc.perform(post("/updateTeacher/3").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/updateTeacher/3"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void postUpdateTeacherFAIL(String username, String pwd) throws Exception {
        mockMvc.perform(post("/updateTeacher/3").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().isForbidden());
    }

    // user and GuardianUser CRUD tests ===============================================================================
    //context loads adminUsers, teacherUsers, followed by guardianUsers
    //IDs are [1,2], [3,4] and [5,6] respectively

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void getCreateGuardian(String username, String pwd) throws Exception {
        mockMvc.perform(get("/createGuardian").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("guardianCreate"))
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("newUser"))
                .andExpect(model().attributeExists("newGuardian"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void getCreateGuardian_FAIL(String username, String pwd) throws Exception {
        mockMvc.perform(get("/createGuardian").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void postCreateGuardian(String username, String pwd) throws Exception {
        when(userServiceTEST.findByUsername(anyString())).thenReturn(
                User.builder().username("the dude").password("weakpwd").build());
        when(guardianUserServiceTEST.findByGuardianUserName(anyString())).thenReturn(
                GuardianUser.builder().guardianUserName("guardian").build());

        mockMvc.perform(post("/createGuardian").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/adminPage"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void postCreateGuardian_FAIL(String username, String pwd) throws Exception {
        mockMvc.perform(post("/createGuardian").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().isForbidden());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void getUpdateGuardian(String username, String pwd) throws Exception {
        mockMvc.perform(get("/updateGuardian/5").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("guardianUpdate"))
                .andExpect(model().attributeExists("user"))
                .andExpect(model().attributeExists("currentGuardianUser"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void getUpdateGuardianNOTFOUND(String username, String pwd) throws Exception {
        mockMvc.perform(get("/updateGuardian/1").with(httpBasic(username, pwd)))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/adminPage"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void getUpdateGuardian_FAIL(String username, String pwd) throws Exception {
        mockMvc.perform(get("/updateGuardian/6").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolAdminUsers")
    @ParameterizedTest
    void postUpdateGuardian(String username, String pwd) throws Exception {
        mockMvc.perform(post("/updateGuardian/5").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/updateGuardian/5"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void postUpdateGuardianFAIL(String username, String pwd) throws Exception {
        mockMvc.perform(post("/updateGuardian/6").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().isForbidden());
    }
}