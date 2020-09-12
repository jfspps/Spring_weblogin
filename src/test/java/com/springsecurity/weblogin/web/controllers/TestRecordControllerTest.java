package com.springsecurity.weblogin.web.controllers;

import com.springsecurity.weblogin.model.TestRecord;
import com.springsecurity.weblogin.model.security.GuardianUser;
import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.services.TestRecordService;
import com.springsecurity.weblogin.services.securityServices.GuardianUserService;
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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Transactional
@Slf4j
@SpringBootTest
class TestRecordControllerTest extends SecurityCredentialsTest {

    //tests will fail unless set to @Transactional (Spring Security does not have JPA persistence)

    //testRecordService is already injected into TestRecordControllerTest
    @Mock
    TestRecordService testRecordServiceTEST;

    @Mock
    UserService userServiceTEST;

    @Mock
    GuardianUserService guardianUserService;

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

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolStaff")
    @ParameterizedTest
    void getCreatePage(String username, String pwd) throws Exception {
        mockMvc.perform(get("/createTestRecord").with(httpBasic(username, pwd)))
                .andExpect(status().isOk())
                .andExpect(view().name("testRecordCreate"))
                .andExpect(model().attributeExists("newTestRecord"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllGuardians")
    @ParameterizedTest
    void getCreatePageGuardiansFORBIDDEN(String username, String pwd) throws Exception {
        mockMvc.perform(get("/createTestRecord").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @Test
    void getCreatePageDENIED() throws Exception {
        mockMvc.perform(get("/createTestRecord"))
                .andExpect(status().isUnauthorized());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolStaff")
    @ParameterizedTest
    void postCreateTestRecord_NEW(String username, String pwd) throws Exception {
        //assume here that the submitted record name does not exist
        mockMvc.perform(post("/createTestRecord").with(csrf())
                    .with(httpBasic(username, pwd))
                    .param("recordName", "some new record")
                    .param("username", "paulsmith")
                    .flashAttr("newTestRecord", TestRecord.builder().build())
                    .flashAttr("guardianUser", User.builder().build()))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/testRecord"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolStaff")
    @ParameterizedTest
    void postCreateTestRecord_ALREADYEXISTS(String username, String pwd) throws Exception {
        //assume here that the submitted record name does exist (somehow)
        mockMvc.perform(post("/createTestRecord").with(csrf())
                .with(httpBasic(username, pwd))
                .param("recordName", "Test record 1")
                .param("username", "paulsmith")
                .flashAttr("newTestRecord", TestRecord.builder().build())
                .flashAttr("guardianUser", User.builder().build()))
                .andExpect(status().is2xxSuccessful())
                .andExpect(view().name("testRecordCreate"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllGuardians")
    @ParameterizedTest
    void postCreateTestRecordGuardiansFORBIDDEN(String username, String pwd) throws Exception {
        mockMvc.perform(post("/createTestRecord").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @Test
    void postCreateTestRecordDENIED() throws Exception {
        mockMvc.perform(post("/createTestRecord").with(csrf()))
                .andExpect(status().isUnauthorized());
    }

    //test Guardian with ID 5 associated with testRecord ID 1
    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolStaff")
    @ParameterizedTest
    void postUpdateTestRecord(String username, String pwd) throws Exception {
        mockMvc.perform(post("/5/updateTestRecord/1")
                .with(httpBasic(username, pwd))
                .with(csrf())
                .param("recordName", "something"))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/testRecord"));
    }

    //test Guardian with ID 6 associated with testRecord ID 1 (assign a testRecord to parents...)
    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolStaff")
    @ParameterizedTest
    void postUpdateTestRecord_newPairing(String username, String pwd) throws Exception {
        mockMvc.perform(post("/6/updateTestRecord/1")
                    .with(httpBasic(username, pwd))
                    .with(csrf())
                    .param("recordName", "something"))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/testRecord"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolStaff")
    @ParameterizedTest
    void postUpdateTestRecord_blankRecordName(String username, String pwd) throws Exception {
        mockMvc.perform(post("/6/updateTestRecord/1")
                .with(httpBasic(username, pwd))
                .with(csrf())
                .param("recordName", ""))
                .andExpect(status().is2xxSuccessful())
                .andExpect(view().name("testRecordUpdate"))
                .andExpect(model().attributeExists("testRecord"))
                .andExpect(model().attributeExists("guardian"))
                .andExpect(model().attributeExists("error"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolStaff")
    @ParameterizedTest
    void postUpdateTestRecord_alreadyExists(String username, String pwd) throws Exception {
        mockMvc.perform(post("/5/updateTestRecord/1")
                .with(httpBasic(username, pwd))
                .with(csrf())
                .param("recordName", "Test record 1"))
                .andExpect(status().is2xxSuccessful())
                .andExpect(view().name("testRecordUpdate"))
                .andExpect(model().attributeExists("testRecord"))
                .andExpect(model().attributeExists("guardian"))
                .andExpect(model().attributeExists("error"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllGuardians")
    @ParameterizedTest
    void postUpdateTestRecordGuardiansFORBIDDEN(String username, String pwd) throws Exception {
        mockMvc.perform(post("/updateTestRecord/1").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @Test
    void postUpdateTestRecordDENIED() throws Exception {
        mockMvc.perform(post("/updateTestRecord/1"))
                .andExpect(status().is4xxClientError());
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamSchoolStaff")
    @ParameterizedTest
    void postDeleteTestRecord(String username, String pwd) throws Exception {
        mockMvc.perform(post("/deleteTestRecord/1").with(httpBasic(username, pwd)).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(view().name("redirect:/testRecord"));
    }

    @MethodSource("com.springsecurity.weblogin.web.controllers.SecurityCredentialsTest#streamAllGuardians")
    @ParameterizedTest
    void postDeleteTestRecordGuardiansFORBIDDEN(String username, String pwd) throws Exception {
        mockMvc.perform(post("/deleteTestRecord/1").with(httpBasic(username, pwd)))
                .andExpect(status().isForbidden());
    }

    @Test
    void postDeleteTestRecordDENIED() throws Exception {
        mockMvc.perform(post("/deleteTestRecord/1"))
                .andExpect(status().is4xxClientError());
    }
}