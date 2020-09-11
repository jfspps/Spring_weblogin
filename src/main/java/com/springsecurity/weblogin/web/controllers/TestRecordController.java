package com.springsecurity.weblogin.web.controllers;

import com.springsecurity.weblogin.exceptions.NotFoundException;
import com.springsecurity.weblogin.model.TestRecord;
import com.springsecurity.weblogin.model.security.Authority;
import com.springsecurity.weblogin.model.security.GuardianUser;
import com.springsecurity.weblogin.model.security.Role;
import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.services.TestRecordService;
import com.springsecurity.weblogin.services.securityServices.AuthorityService;
import com.springsecurity.weblogin.services.securityServices.GuardianUserService;
import com.springsecurity.weblogin.services.securityServices.RoleService;
import com.springsecurity.weblogin.services.securityServices.UserService;
import com.springsecurity.weblogin.web.permissionAnnot.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.swing.*;
import javax.validation.Valid;
import java.util.Set;

@Controller
@RequiredArgsConstructor
@Slf4j
public class TestRecordController {

    private final TestRecordService testRecordService;
    private final UserService userService;
    private final GuardianUserService guardianUserService;

    //prevent the HTTP form POST from editing listed properties
    @InitBinder
    public void setAllowedFields(WebDataBinder dataBinder) {
        dataBinder.setDisallowedFields("id");
    }

    @ModelAttribute("testRecordSet")
    public Set<TestRecord> populateTestRecords() {
        return testRecordService.findAll();
    }

    //pass the authenticated user from the context with @AuthenticationPrincipal
    @GuardianRead
    @GetMapping("/testRecord")
    public String getCRUDpage(@AuthenticationPrincipal User user, Model model) {
        // the authenticated user is injected into the current session. If the authenticated user belongs to a
        // teacher or admin User (user.getTeacherUser and user.getAdminUser) then all records are presented
        if (user.getGuardianUser() != null) {
            model.addAttribute("testRecords", testRecordService.findAllTestRecordsByUsername(user.getUsername()));
        } else {
            //if the user falls under AdminUser, UserUser or TeacherUser...
            model.addAttribute("testRecords", testRecordService.findAll());
        }
        model.addAttribute("userID", user.getId());
        return "testRecord";
    }

    @TeacherCreate
    @GetMapping("/createTestRecord")
    public String createTestRecord(Model model) {
        model.addAttribute("newTestRecord", new TestRecord());
        model.addAttribute("guardianUser", new User());
        return "testRecordCreate";
    }

    @TeacherCreate
    @PostMapping("/createTestRecord")
    public String createTestRecordPOST(@Valid @ModelAttribute("newTestRecord") TestRecord testRecord, BindingResult TRbindingResult,
                                       @Valid @ModelAttribute("guardianUser") User guardianUser, BindingResult GbindingResult) {
        if (!testRecord.getRecordName().isEmpty() && !guardianUser.getUsername().isEmpty()) {
            //check that the testRecord does not already exist for the given Guardian
            TestRecord TRfound = testRecordService.findByRecordName(testRecord.getRecordName());
            GuardianUser Gfound = guardianUserService.findByGuardianUserName(guardianUser.getUsername());
            if (!TRfound.getUser().getGuardianUser().equals(Gfound)) {
                TestRecord saved = testRecordService.createTestRecord(testRecord.getRecordName(), guardianUser.getUsername());
                log.debug("Received guardianUser with id: " + saved.getUser().getId()
                        + " and username: " + saved.getUser().getUsername());
            } else {
                log.debug("TestRecord is already associated with the provided Guardian details. No changes made.");
            }
        } else {
            TRbindingResult.getAllErrors().forEach(objectError -> {
                log.debug("testRecord: " + objectError.toString());  //use to build custom messages
            });
            GbindingResult.getAllErrors().forEach(objectError -> {
                log.debug("GuardianUser: " + objectError.toString());
            });
            log.debug("TestRecord not saved to DB");
            return "testRecordCreate";
        }
        return "redirect:/testRecord";
    }

    @TeacherRead
    @GetMapping("/testRecord/{id}")
    public String getTestRecordById(@PathVariable String id, Model model) {
        if (testRecordService.findById(Long.valueOf(id)) == null) {
            log.debug("TestRecord with ID: " + id + " not found");
            throw new NotFoundException("TestRecord with ID: " + id + " not found");
        }
        TestRecord found = testRecordService.findById(Long.valueOf(id));
        User guardian = found.getUser();
        model.addAttribute("guardian", guardian);
        model.addAttribute("testRecord", found);
        return "testRecordUpdate";
    }

    @TeacherUpdate
    @PostMapping("/{guardianId}/updateTestRecord/{testRecordID}")
    public String updateTestRecord(@Valid @ModelAttribute("testRecord") TestRecord testRecord,
                                   @PathVariable String testRecordID, @PathVariable String guardianId) {
        if (testRecord.getRecordName() == null || userService.findById(Long.valueOf(guardianId)) == null) {
            log.debug("Record name and valid User (guardian) ID are required");
            return "redirect:/testRecord";
        } else {
            log.debug("Guardian ID: " + guardianId + ", testRecord string: " + testRecord.getRecordName() + " submitted");
            //check whether the new testRecord as per the form already exists
            if (testRecordService.findByRecordName(testRecord.getRecordName()) != null) {
                //check whether the testRecord as per the form is already assigned to the current Guardian
                TestRecord testRecordByForm = testRecordService.findByRecordName(testRecord.getRecordName());
                GuardianUser currentGuardian = guardianUserService.findById(Long.valueOf(guardianId));

                if (!testRecordByForm.getUser().getGuardianUser().equals(currentGuardian)) {
                    TestRecord testRecordOnFile = testRecordService.findById(Long.valueOf(testRecordID));
                    testRecordService.updateTestRecord(Long.valueOf(testRecordID),
                            testRecordOnFile.getUser().getId(), testRecord.getRecordName());
                } else {
                    log.debug("The current guardian is already assigned a testRecord with the given values. " +
                            "No changes made");
                }
            } else {
                TestRecord testRecordOnFile = testRecordService.findById(Long.valueOf(testRecordID));
                testRecordService.updateTestRecord(Long.valueOf(testRecordID),
                        testRecordOnFile.getUser().getId(), testRecord.getRecordName());
            }
        }
        return "redirect:/testRecord";
    }

    @TeacherDelete
    @PostMapping("/deleteTestRecord/{testRecordID}")
    public String deleteTestRecord(@Valid @ModelAttribute("testRecord") TestRecord testRecord,
                                   @PathVariable String testRecordID) {
        if (testRecordService.findById(Long.valueOf(testRecordID)) == null) {
            log.debug("No record on file with id: " + testRecordID + ", nothing deleted");
            return "redirect:/testRecord";
        } else {
            User associatedUser = testRecordService.findById(Long.valueOf(testRecordID)).getUser();
            testRecordService.deleteTestRecordAndUpdateUser(Long.valueOf(testRecordID), associatedUser);
        }
        return "redirect:/testRecord";
    }
}
