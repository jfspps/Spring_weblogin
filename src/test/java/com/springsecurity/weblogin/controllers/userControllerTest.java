package com.springsecurity.weblogin.controllers;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Slf4j
@WebMvcTest
class userControllerTest {

    @Autowired
    WebApplicationContext context;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @WithAnonymousUser
    @Test
    void welcomePage() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(view().name("welcome"));
    }

    //this passes with any username
    @WithMockUser("admin")
    @Test
    void loginPage_admin() throws Exception {
        mockMvc.perform(get("/authenticated"))
                .andExpect(status().isOk())
                .andExpect(view().name("authenticated"));
    }

    //this passes with any username
    @WithMockUser("random")
    @Test
    void loginPage_random() throws Exception {
        mockMvc.perform(get("/authenticated"))
                .andExpect(status().isOk())
                .andExpect(view().name("authenticated"));
    }

    //default is Spring's "user" (coincidental that my 'user' has the same name as Spring's)
    @WithMockUser()
    @Test
    void loginPage_user() throws Exception {
        mockMvc.perform(get("/authenticated"))
                .andExpect(status().isOk())
                .andExpect(view().name("authenticated"))
                .andExpect(model().attributeExists("user"));
    }

    @WithAnonymousUser
    @Test
    void redirectToLoginWhenRequestingAuthenticated_User() throws Exception {
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
                        .param("username", "user")
                        .param("password", "user123")
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

    @Test
    void loginAuthHttpBasicUserPASS() throws Exception {
        mockMvc.perform(get("/authenticated").with(httpBasic("user", "user123")))
                .andExpect(status().isOk())
                .andExpect(view().name("authenticated"))
                .andExpect(model().attributeExists("user"));
    }

    @Test
    void loginAuthHttpBasicAdminPASS() throws Exception {
        mockMvc.perform(get("/authenticated").with(httpBasic("admin", "admin123")))
                .andExpect(status().isOk())
                .andExpect(view().name("authenticated"));
    }

    @Test
    void loginAuthHttpBasicFAIL() throws Exception {
        MvcResult unauthenticatedResult = mockMvc.perform(get("/authenticated").with(httpBasic("randomPerson", "xyz")))
                .andExpect(status().is4xxClientError())
                .andReturn();

        //not printing anything it seems...
        log.debug("loginAuthHttpBasicFAIL(), redirected URL: " + unauthenticatedResult.getResponse().getContentAsString());
    }

    @Test
    void userPage_withUser() throws Exception {
        mockMvc.perform(get("/userPage").with(httpBasic("user", "user123")))
                .andExpect(status().isOk())
                .andExpect(view().name("userPage"));
    }

    @Test
    void userPage_withAdmin() throws Exception {
        mockMvc.perform(get("/userPage").with(httpBasic("admin", "admin123")))
                .andExpect(status().isOk())
                .andExpect(view().name("userPage"));
    }

    @Test
    void adminPage_withAdmin() throws Exception {
        mockMvc.perform(get("/adminPage").with(httpBasic("admin", "admin123")))
                .andExpect(status().isOk())
                .andExpect(view().name("adminPage"));
    }

    @Test
    void adminPage_withUser() throws Exception {
        mockMvc.perform(get("/adminPage").with(httpBasic("user", "user123")))
                .andExpect(status().is4xxClientError());
    }

    @Test
    void logoutPage() throws Exception {
        mockMvc.perform(get("/logout"))
                .andExpect(status().is2xxSuccessful());
    }
}