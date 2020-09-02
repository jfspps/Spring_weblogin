package com.springsecurity.weblogin.web.controllers;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.stream.Stream;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

//USER <--> ROLE <--> AUTHORITY

@Slf4j
@SpringBootTest
//substitute @WebMvcTest for @SpringBootTest to guarantee tests capture all Spring Boot dependencies which were loaded at the time
class UserControllerTest extends SecurityCredentialsTest {

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
                .andExpect(status().isOk());
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
                .andExpect(status().isOk());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllUsers")
    @ParameterizedTest
    void loginAuthHttpBasic_AllUsers_Authenticated(String username, String pwd) throws Exception {
        mockMvc.perform(get("/authenticated").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("authenticated"))
                .andExpect(model().attributeExists("user"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllUsers")
    @ParameterizedTest
    void loginAuthHttpBasic_AllUsers_UserPage(String username, String pwd) throws Exception {
        mockMvc.perform(get("/userPage").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("userPage"))
                .andExpect(model().attributeExists("user"));
    }

    @Test
    void loginAuthHttpBasicFAIL() throws Exception {
        MvcResult unauthenticatedResult = mockMvc.perform(get("/authenticated").with(httpBasic("randomPerson", "xyz")))
                .andExpect(status().isUnauthorized())
                .andReturn();

        //not printing anything it seems...
        System.out.println("loginAuthHttpBasicFAIL(), redirected URL: " + unauthenticatedResult.getResponse().getContentAsString());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllUsers")
    @ParameterizedTest
    void userPage_withAllUsers(String username, String pwd) throws Exception {
        mockMvc.perform(get("/userPage").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("userPage"));
    }

    @WithUserDetails("admin")
    @Test
    void adminPagePASS_withAdmin() throws Exception {
        mockMvc.perform(get("/adminPage"))
                .andExpect(status().isOk())
                .andExpect(view().name("adminPage"));
    }

    //same test as above with new annotation (username and pwd are pulled from JPAUserDetails)
    @Test
    @WithUserDetails("admin")
    void adminPagePASS_withAdmin_withoutHttpBasic() throws Exception {
        mockMvc.perform(get("/adminPage"))
                .andExpect(status().isOk())
                .andExpect(view().name("adminPage"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllNonAdminUsers")
    @ParameterizedTest
    void adminPageFAIL_withNonAdmin(String username, String pwd) throws Exception {
        mockMvc.perform(get("/adminPage").with(httpBasic(username, pwd)))
                .andExpect(status().is4xxClientError());
    }

    @Test
    void logoutPage() throws Exception {
        mockMvc.perform(get("/logout"))
                .andExpect(status().is2xxSuccessful());
    }
}