package com.springsecurity.weblogin.web.controllers;

import com.springsecurity.weblogin.model.TestRecord;
import com.springsecurity.weblogin.model.security.Authority;
import com.springsecurity.weblogin.model.security.GuardianUser;
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

    public TestRecordController(TestRecordService testRecordService, UserService userService) {
        this.testRecordService = testRecordService;
        this.userService = userService;
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
        log.debug("User logged in: " + user.getUsername());

        // the authenticated user is injected into the current session. If the authenticated user belongs to a
        // teacher or admin User (user.getTeacherUser and user.getAdminUser) then all records are presented
        if (user.getGuardianUser() != null){
            model.addAttribute("testRecords", testRecordService.findAllTestRecordsByUsername(user.getUsername()));
        } else {
            //if the user falls under AdminUser, UserUser or TeacherUser...
            model.addAttribute("testRecords", testRecordService.findAll());
        }
        return "testRecord";
    }

    @TeacherCreate
    @GetMapping("/createTestRecord")
    public String createTestRecord(Model model){
        model.addAttribute("newTestRecord", new TestRecord());
        model.addAttribute("guardianUser", new User());
        return "testRecordCreate";
    }

    @TeacherCreate
    @PostMapping("/createTestRecord")
    public String createTestRecordPOST(@Valid @ModelAttribute("newTestRecord") TestRecord testRecord,
                                       @Valid @ModelAttribute("guardianUser") User guardianUser){
        if (testRecord.getRecordName() != null && guardianUser.getUsername() != null){
            TestRecord saved = testRecordService.createTestRecord(testRecord.getRecordName(), guardianUser.getUsername());
            log.debug("Received guardianUser with id: " + saved.getUser().getId()
                    + " and username: " + saved.getUser().getUsername());
        } else
            log.debug("TestRecord not saved to DB");
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
    @PostMapping("/updateTestRecord/{testRecordID}")
    public String updateTestRecord(@Valid @ModelAttribute("testRecord") TestRecord testRecord,
                                   @PathVariable String testRecordID){
        if (testRecord.getRecordName() == null){
            log.debug("Record name required");
            return "redirect:/testRecord";
        } else {
            TestRecord found = testRecordService.findById(Long.valueOf(testRecordID));
            testRecordService.updateTestRecord(Long.valueOf(testRecordID), found.getUser().getId(), testRecord.getRecordName());
        }
        return "redirect:/testRecord";
    }

    @TeacherDelete
    @PostMapping("/deleteTestRecord/{testRecordID}")
    public String deleteTestRecord(@Valid @ModelAttribute("testRecord") TestRecord testRecord,
                                   @PathVariable String testRecordID){
        if (testRecordService.findById(Long.valueOf(testRecordID)) == null){
            log.info("No record on file with id: " + testRecordID + ", nothing deleted");
        } else {
            User associatedUser = testRecordService.findById(Long.valueOf(testRecordID)).getUser();
            testRecordService.deleteTestRecordAndUpdateUser(Long.valueOf(testRecordID), associatedUser);
        }
        return "redirect:/testRecord";
    }
}
