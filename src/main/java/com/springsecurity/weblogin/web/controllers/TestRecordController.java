package com.springsecurity.weblogin.web.controllers;

import com.springsecurity.weblogin.model.TestRecord;
import com.springsecurity.weblogin.model.security.Authority;
import com.springsecurity.weblogin.model.security.Role;
import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.services.TestRecordService;
import com.springsecurity.weblogin.services.securityServices.AuthorityService;
import com.springsecurity.weblogin.services.securityServices.RoleService;
import com.springsecurity.weblogin.services.securityServices.UserService;
import com.springsecurity.weblogin.web.permissionAnnot.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.Set;

@Controller
@Slf4j
public class TestRecordController {

    private final TestRecordService testRecordService;
    private final UserService userService;
    private final AuthorityService authorityService;


    public TestRecordController(TestRecordService testRecordService, UserService userService, AuthorityService authorityService) {
        this.testRecordService = testRecordService;
        this.userService = userService;
        this.authorityService = authorityService;
    }

    //prevent the HTTP form POST from editing listed properties
    @InitBinder
    public void setAllowedFields(WebDataBinder dataBinder){
        dataBinder.setDisallowedFields("id");
    }

    @ModelAttribute("testRecordSet")
    public Set<TestRecord> populateTestRecords() {
        return testRecordService.findAll();
    }

    //pass the authenticated user from the context with @AuthenticationPrincipal
    @GuardianRead
    @GetMapping("/testRecord")
    public String getCRUDpage(@AuthenticationPrincipal User user, Model model){
        //add logic to check for adminUser or teacherUser
        model.addAttribute("testRecords", testRecordService.findAllTestRecordsByUsername(user.getUsername()));
        return "testRecord";
    }

    @TeacherCreate
    @GetMapping("/createTestRecord")
    public String createTestRecord(Model model){
        model.addAttribute("newTestRecord", new TestRecord());
        return "testRecordCreate";
    }

    @TeacherCreate
    @PostMapping("/createTestRecord")
    public String createTestRecordPOST(@Valid @ModelAttribute("newTestRecord") TestRecord testRecord){
        TestRecord saved = testRecordService.save(testRecord);
        log.debug("Received testRecord with id: " + saved.getId() + " and name: " + saved.getRecordName());
        return "redirect:/testRecord";
    }

    @TeacherRead
    @GetMapping("/testRecord/{id}")
    public String getTestRecordById(@PathVariable String id, Model model){
        TestRecord found = testRecordService.findById(Long.valueOf(id));
        model.addAttribute("testRecord", found);
        return "testRecordUpdate";
    }

    @TeacherUpdate
    @PostMapping("/updateTestRecord/{id}")
    public String updateTestRecord(@Valid @ModelAttribute("testRecord") TestRecord testRecord,
                                   @PathVariable String id){
        TestRecord saved;
        if (testRecordService.findByName(testRecord.getRecordName()) == null){
            TestRecord temp = testRecordService.findById(Long.valueOf(id));
            temp.setRecordName(testRecord.getRecordName());
            saved = testRecordService.save(temp);
        } else {
            log.info("Record with the name " + testRecord.getRecordName() + " already exists");
            saved = testRecordService.findByName(testRecord.getRecordName());
        }
        log.info("Record with id " + saved.getId() + " and record name: " + saved.getRecordName());
        return "redirect:/testRecord";
    }

    @TeacherDelete
    @PostMapping("/deleteTestRecord/{id}")
    public String deleteTestRecord(@Valid @ModelAttribute("testRecord") TestRecord testRecord,
                                   @PathVariable String id){
        if (testRecordService.findById(Long.valueOf(id)) == null){
            log.info("No record on file with id: " + id + ", nothing deleted");
        } else {
            testRecordService.deleteById(Long.valueOf(id));
            log.info("TestRecord with id: " + id + " deleted");
        }
        return "redirect:/testRecord";
    }
}
