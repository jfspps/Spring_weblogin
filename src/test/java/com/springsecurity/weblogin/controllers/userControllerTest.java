package com.springsecurity.weblogin.controllers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

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

    @WithMockUser("admin")
    @Test
    void loginPage_admin() throws Exception {
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
                .andExpect(view().name("authenticated"));
    }

    @WithAnonymousUser
    @Test
    void redirectToLogin() throws Exception {
        mockMvc.perform(get("/authenticated"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlTemplate("http://localhost/login"));
    }

    @Test
    void loginError() {

    }

    @Test
    void userLogin() {
    }

    @Test
    void userPage() {
    }

    @Test
    void adminPage() {
    }

    @Test
    void logoutPage() {
    }
}