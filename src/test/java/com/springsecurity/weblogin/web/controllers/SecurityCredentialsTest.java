package com.springsecurity.weblogin.web.controllers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.provider.Arguments;
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

    private final static String JOHNSMITH_ADMINPWD = "johnsmith123";
    private final static String AMYSMITH_ADMINPWD = "amysmith123";
    private final static String PAULSMITH_GUARDIANPWD = "paulsmith123";
    private final static String ALEXSMITH_GUARDIANPWD = "alexsmith123";
    private final static String KEITHJONES_TEACHERPWD = "keithjones123";
    private final static String MARYMANNING_TEACHERPWD = "marymanning123";

    // provides all users to perform a given test (the order of the username and pwd parameters is important)
    public static Stream<Arguments> streamAllUsers(){
        return Stream.of(Arguments.of("paulsmith", PAULSMITH_GUARDIANPWD),
                Arguments.of("alexsmith", ALEXSMITH_GUARDIANPWD),
                Arguments.of("keithjones", KEITHJONES_TEACHERPWD),
                Arguments.of("marymanning", MARYMANNING_TEACHERPWD),
                Arguments.of("johnsmith", JOHNSMITH_ADMINPWD),
                Arguments.of("amysmith", AMYSMITH_ADMINPWD));
    }

    public static Stream<Arguments> streamSchoolStaff(){
        return Stream.of(Arguments.of("keithjones", KEITHJONES_TEACHERPWD),
                Arguments.of("marymanning", MARYMANNING_TEACHERPWD),
                Arguments.of("johnsmith", JOHNSMITH_ADMINPWD),
                Arguments.of("amysmith", AMYSMITH_ADMINPWD));
    }

    // provides non-Admin users to perform a given test
    public static Stream<Arguments> streamAllNonAdminUsers(){
        return Stream.of(Arguments.of("paulsmith", PAULSMITH_GUARDIANPWD),
                Arguments.of("alexsmith", ALEXSMITH_GUARDIANPWD),
                Arguments.of("keithjones", KEITHJONES_TEACHERPWD),
                Arguments.of("marymanning", MARYMANNING_TEACHERPWD));
    }

    public static Stream<Arguments> streamAllGuardians(){
        return Stream.of(Arguments.of("paulsmith", PAULSMITH_GUARDIANPWD),
                Arguments.of("alexsmith", ALEXSMITH_GUARDIANPWD));
    }

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }
}
