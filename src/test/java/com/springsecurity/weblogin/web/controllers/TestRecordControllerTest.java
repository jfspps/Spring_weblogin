package com.springsecurity.weblogin.web.controllers;

import com.springsecurity.weblogin.model.TestRecord;
import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.services.TestRecordService;
import com.springsecurity.weblogin.services.securityServices.UserService;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;

import javax.transaction.Transactional;
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

    //tests will fail unless set to @Transactional (Spring Security does not have JPA persistence)

    //testRecordService is already injected into TestRecordControllerTest
    @Mock
    TestRecordService testRecordServiceTEST;

    @Mock
    UserService userServiceTEST;

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllUsers")
    @ParameterizedTest
    void getCRUDpage(String username, String pwd) throws Exception {
        mockMvc.perform(get("/testRecord").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("testRecord"))
                .andExpect(model().attributeExists("testRecords"));
    }

    @Test
    void getCRUDpageAnonDENIED() throws Exception {
        mockMvc.perform(get("/testRecord"))
                .andExpect(status().isUnauthorized());
    }

    @Transactional
    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolStaff")
    @ParameterizedTest
    void getCreatePage(String username, String pwd) throws Exception {
        mockMvc.perform(get("/createTestRecord").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("testRecordCreate"))
                .andExpect(model().attributeExists("newTestRecord"));
    }

    @Transactional
    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllGuardians")
    @ParameterizedTest
    void getCreatePageGuardiansFORBIDDEN(String username, String pwd) throws Exception {
        mockMvc.perform(get("/createTestRecord").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @Transactional
    @Test
    void getCreatePageDENIED() throws Exception {
        mockMvc.perform(get("/createTestRecord"))
                .andExpect(status().isUnauthorized());
    }

    @Transactional
    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolStaff")
    @ParameterizedTest
    void postCreateTestRecord(String username, String pwd) throws Exception {
        when(userServiceTEST.save(any())).thenReturn(User.builder().build());
        when(userServiceTEST.findByUsername(anyString())).thenReturn(User.builder().build());
        when(testRecordServiceTEST.save(any())).thenReturn(TestRecord.builder().build());
        when(testRecordServiceTEST.createTestRecord(anyString(), anyString())).thenReturn(TestRecord.builder().build());

        mockMvc.perform(post("/createTestRecord")
                    .with(httpBasic(username, pwd))
                    .flashAttr("newTestRecord", TestRecord.builder().build())
                    .flashAttr("guardianUser", User.builder().build()))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/testRecord"));
    }

    @Transactional
    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllGuardians")
    @ParameterizedTest
    void postCreateTestRecordGuardiansFORBIDDEN(String username, String pwd) throws Exception {
        mockMvc.perform(post("/createTestRecord").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @Transactional
    @Test
    void postCreateTestRecordDENIED() throws Exception {
        mockMvc.perform(post("/createTestRecord"))
                .andExpect(status().isUnauthorized());
    }

    @Transactional
    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolStaff")
    @ParameterizedTest
    void postUpdateTestRecord(String username, String pwd) throws Exception {
        TestRecord testRecord = new TestRecord();
        when(testRecordServiceTEST.save(any())).thenReturn(testRecord);
        when(testRecordServiceTEST.findByName(anyString())).thenReturn(testRecord);
        when(testRecordServiceTEST.findById(anyLong())).thenReturn(testRecord);

        mockMvc.perform(post("/updateTestRecord/1").with(httpBasic(username, pwd)))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/testRecord"));
    }

    @Transactional
    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllGuardians")
    @ParameterizedTest
    void postUpdateTestRecordGuardiansFORBIDDEN(String username, String pwd) throws Exception {
        mockMvc.perform(post("/updateTestRecord/1").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @Transactional
    @Test
    void postUpdateTestRecordDENIED() throws Exception {
        mockMvc.perform(post("/updateTestRecord/1"))
                .andExpect(status().is4xxClientError());
    }

    @Transactional
    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolStaff")
    @ParameterizedTest
    void postDeleteTestRecord(String username, String pwd) throws Exception {
        when(testRecordServiceTEST.findById(anyLong())).thenReturn(TestRecord.builder().build());

        mockMvc.perform(post("/deleteTestRecord/1").with(httpBasic(username, pwd)))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/testRecord"));
    }

    @Transactional
    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllGuardians")
    @ParameterizedTest
    void postDeleteTestRecordGuardiansFORBIDDEN(String username, String pwd) throws Exception {
        mockMvc.perform(post("/deleteTestRecord/1").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @Transactional
    @Test
    void postDeleteTestRecordDENIED() throws Exception {
        mockMvc.perform(post("/deleteTestRecord/1"))
                .andExpect(status().is4xxClientError());
    }
}