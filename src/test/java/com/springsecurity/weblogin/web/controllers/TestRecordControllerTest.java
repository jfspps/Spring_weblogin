package com.springsecurity.weblogin.web.controllers;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Slf4j
@SpringBootTest
class TestRecordControllerTest extends SecurityCredentialsTest {

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllUsers")
    @ParameterizedTest
    void getCRUDpage(String username, String pwd) throws Exception {
        mockMvc.perform(get("/testRecord").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("testRecord"))
                .andExpect(model().attributeExists("testRecords"));
    }
}