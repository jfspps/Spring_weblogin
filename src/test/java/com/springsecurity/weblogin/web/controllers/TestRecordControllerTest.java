package com.springsecurity.weblogin.web.controllers;

import com.springsecurity.weblogin.model.TestRecord;
import com.springsecurity.weblogin.services.TestRecordService;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Slf4j
@SpringBootTest
class TestRecordControllerTest extends SecurityCredentialsTest {

    //testRecordService is already injected into TestRecordControllerTest
    @Mock
    TestRecordService testRecordServiceTEST;

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllUsers")
    @ParameterizedTest
    void getCRUDpage(String username, String pwd) throws Exception {
        mockMvc.perform(get("/testRecord").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("testRecord"))
                .andExpect(model().attributeExists("testRecords"));   //matches the no. of TestRecords on bootloader
    }

    @Test
    void getCRUDpageDENIED() throws Exception {
        mockMvc.perform(get("/testRecord"))
                .andExpect(status().isUnauthorized());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllUsers")
    @ParameterizedTest
    void getCreatePage(String username, String pwd) throws Exception {
        mockMvc.perform(get("/createTestRecord").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("testRecordCreate"))
                .andExpect(model().attributeExists("newTestRecord"));
    }

    @Test
    void getCreatePageDENIED() throws Exception {
        mockMvc.perform(get("/createTestRecord"))
                .andExpect(status().isUnauthorized());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllUsers")
    @ParameterizedTest
    void postCreateTestRecord(String username, String pwd) throws Exception {
        mockMvc.perform(post("/createTestRecord").with(httpBasic(username, pwd)))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/testRecord"));
    }

    @Test
    void postCreateTestRecordDENIED() throws Exception {
        mockMvc.perform(post("/createTestRecord"))
                .andExpect(status().isUnauthorized());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllUsers")
    @ParameterizedTest
    void getUpdateTestRecord(String username, String pwd) throws Exception {
        mockMvc.perform(post("/createTestRecord").with(httpBasic(username, pwd)))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/testRecord"));
    }

    @Test
    void getUpdateTestRecordDENIED() throws Exception {
        mockMvc.perform(post("/createTestRecord"))
                .andExpect(status().isUnauthorized());
    }

    //this fails when the entire test class is run but passes when run independently

//    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllUsers")
//    @ParameterizedTest
//    void postUpdateTestRecord(String username, String pwd) throws Exception {
//        TestRecord testRecord = new TestRecord();
//        when(testRecordServiceTEST.save(any())).thenReturn(testRecord);
//        when(testRecordServiceTEST.findByName(anyString())).thenReturn(testRecord);
//        when(testRecordServiceTEST.findById(anyLong())).thenReturn(testRecord);
//
//        mockMvc.perform(post("/updateTestRecord/1").with(httpBasic(username, pwd)))
//                .andExpect(status().is3xxRedirection())
//                .andExpect(view().name("redirect:/testRecord"));
//    }

    @Test
    void postUpdateTestRecordDENIED() throws Exception {
        mockMvc.perform(post("/updateTestRecord/1"))
                .andExpect(status().is4xxClientError());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllUsers")
    @ParameterizedTest
    void postDeleteTestRecord(String username, String pwd) throws Exception {
        TestRecord testRecord = new TestRecord();
        when(testRecordServiceTEST.findById(anyLong())).thenReturn(testRecord);

        mockMvc.perform(post("/deleteTestRecord/1").with(httpBasic(username, pwd)))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/testRecord"));
    }

    @Test
    void postDeleteTestRecordDENIED() throws Exception {
        mockMvc.perform(post("/deleteTestRecord/1"))
                .andExpect(status().is4xxClientError());
    }
}