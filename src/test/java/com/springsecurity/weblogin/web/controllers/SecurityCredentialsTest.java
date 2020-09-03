package com.springsecurity.weblogin.web.controllers;

import com.springsecurity.weblogin.services.TestRecordService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.provider.Arguments;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.stream.Stream;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

public abstract class SecurityCredentialsTest {

    @Autowired
    WebApplicationContext context;

    protected MockMvc mockMvc;

    private final static String ADMINPWD = "admin123";
    private final static String JOHNSMITH_ADMINPWD = "johnsmith123";
    private final static String AMYSMITH_ADMINPWD = "amysmith123";
    private final static String USERPWD = "user123";
    private final static String TEACHERPWD = "teacher123";
    private final static String GUARDIAN1PWD = "guardian123";
    private final static String GUARDIAN2PWD = "guardian456";

    // provides all users to perform a given test (the order of the username and pwd parameters is important)
    public static Stream<Arguments> streamAllUsers(){
        return Stream.of(Arguments.of("admin", ADMINPWD),
                Arguments.of("user", USERPWD),
                Arguments.of("teacher", TEACHERPWD),
                Arguments.of("guardian1", GUARDIAN1PWD),
                Arguments.of("guardian2", GUARDIAN2PWD),
                Arguments.of("johnsmith", JOHNSMITH_ADMINPWD),
                Arguments.of("amysmith", AMYSMITH_ADMINPWD));
    }

    // provides non-Admin users to perform a given test
    public static Stream<Arguments> streamAllNonAdminUsers(){
        return Stream.of(Arguments.of("user", USERPWD),
                Arguments.of("teacher", TEACHERPWD),
                Arguments.of("guardian1", GUARDIAN1PWD),
                Arguments.of("guardian2", GUARDIAN2PWD));
    }

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }
}
