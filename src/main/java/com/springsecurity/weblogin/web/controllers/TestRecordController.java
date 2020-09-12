package com.springsecurity.weblogin.web.controllers;

import com.springsecurity.weblogin.exceptions.NotFoundException;
import com.springsecurity.weblogin.model.TestRecord;
import com.springsecurity.weblogin.model.security.GuardianUser;
import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.services.TestRecordService;
import com.springsecurity.weblogin.services.securityServices.GuardianUserService;
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
        if (!TestRecord_GuardianNameFields_AreEmpty(testRecord, guardianUser)) {
            if (userService.findByUsername(guardianUser.getUsername()) != null)  {
                //check if the testRecord, by the submitted form, already exists
                if (testRecordService.findByRecordName(testRecord.getRecordName()) != null) {
                    //another testRecord with the same record name found, see if the current guardian is its 'owner'
                    TestRecord TRfound = testRecordService.findByRecordName(testRecord.getRecordName());
                    User Gfound = userService.findByUsername(guardianUser.getUsername());
                    if (!testRecordBelongsToGuardian(TRfound, Gfound)) {
                        saveTestRecordWithGuardian(testRecord, guardianUser);
                    } else {
                        log.debug("TestRecord is already associated with the provided Guardian details. No changes made.");
                        TRbindingResult.rejectValue("recordName", "exists", "Supplied testRecord already exists");
                        return "testRecordCreate";
                    }
                } else {
                    log.debug("TestRecord not found, saving new testRecord");
                    saveTestRecordWithGuardian(testRecord, guardianUser);
                }
            } else {
                log.debug("Guardian with given (User) username not found");
                GbindingResult.rejectValue("username", "notFound", "Guardian username not found");
                return "testRecordCreate";
            }
        } else {
            log.debug("Both username and record name fields are empty");
            printTestRecordCreateErrors(TRbindingResult, GbindingResult);
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
    public String postUpdateTestRecord(@Valid @ModelAttribute("testRecord") TestRecord testRecord, BindingResult TRbindingResult,
                                   @PathVariable String testRecordID, @PathVariable String guardianId, Model model) {
        if (testRecord.getRecordName().isEmpty()) {
            log.debug("Record name entry is empty");
            TestRecord found = testRecordService.findById(Long.valueOf(testRecordID));

            model.addAttribute("error", "Record name required");
            model.addAttribute("guardian", found.getUser());
            model.addAttribute("testRecord", found);
            return "testRecordUpdate";
        }
        if (userService.findById(Long.valueOf(guardianId)) == null) {
            log.debug("Valid User (guardian) ID are required");
            return "redirect:/testRecord";
        } else {
            log.debug("Guardian ID: " + guardianId + ", testRecord string: " + testRecord.getRecordName() + " submitted");
            //check whether the new testRecord as per the form already exists
            if (testRecordService.findByRecordName(testRecord.getRecordName()) != null) {
                //check whether the testRecord as per the form is already assigned to the current Guardian
                TestRecord testRecordByForm = testRecordService.findByRecordName(testRecord.getRecordName());
                User currentGuardian = userService.findById(Long.valueOf(guardianId));

                if (!testRecordBelongsToGuardian(testRecordByForm, currentGuardian)) {
                    updateTestRecord_recordName(testRecord, testRecordID);
                } else {
                    log.debug("The current guardian is already assigned a testRecord with the given values. " +
                            "No changes made");
                    TRbindingResult.rejectValue("recordName", "exists", "Supplied testRecord already exists");
                    model.addAttribute("testRecord", testRecordByForm);
                    model.addAttribute("guardian", currentGuardian);
                    model.addAttribute("error", "The testRecord supplied is already associated with guardian, "
                            + currentGuardian.getUsername());
                    return "testRecordUpdate";
                }
            } else {
                //testRecord doesn't exist, so save to Guardian's account
                updateTestRecord_recordName(testRecord, testRecordID);
            }
        }
        return "redirect:/testRecord";
    }

    @TeacherDelete
    @PostMapping("/deleteTestRecord/{testRecordID}")
    public String deleteTestRecord(@PathVariable String testRecordID) {
        if (testRecordService.findById(Long.valueOf(testRecordID)) == null) {
            log.debug("No record on file with id: " + testRecordID + ", nothing deleted");
            return "redirect:/testRecord";
        } else {
            User associatedUser = testRecordService.findById(Long.valueOf(testRecordID)).getUser();
            testRecordService.deleteTestRecordAndUpdateUser(Long.valueOf(testRecordID), associatedUser);
        }
        return "redirect:/testRecord";
    }

    // 'ancillary' methods

    private void printTestRecordCreateErrors(BindingResult TRbindingResult, BindingResult GbindingResult) {
        TRbindingResult.getAllErrors().forEach(objectError -> {
            log.debug("testRecord: " + objectError.toString());  //use to build custom messages
        });
        GbindingResult.getAllErrors().forEach(objectError -> {
            log.debug("GuardianUser: " + objectError.toString());
        });
        log.debug("TestRecord not saved to DB");
    }

    private void printTestRecordCreateErrors(BindingResult TRbindingResult) {
        TRbindingResult.getAllErrors().forEach(objectError -> {
            log.debug("testRecord: " + objectError.toString());  //use to build custom messages
        });
        log.debug("TestRecord not saved to DB");
    }

    private void saveTestRecordWithGuardian(TestRecord testRecord, User guardianUser) {
        TestRecord saved = testRecordService.createTestRecord(testRecord.getRecordName(), guardianUser.getUsername());
        log.debug("Received guardianUser with id: " + saved.getUser().getId()
                + " and username: " + saved.getUser().getUsername());
    }

    private boolean testRecordBelongsToGuardian(TestRecord TRfound, User gfound) {
            return TRfound.getUser().getId().equals(gfound.getId());
    }

    private boolean TestRecord_GuardianNameFields_AreEmpty(TestRecord testRecord, User guardianUser) {
        return testRecord.getRecordName().isEmpty() || guardianUser.getUsername().isEmpty();
    }

    private void updateTestRecord_recordName(TestRecord testRecord, String testRecordID) {
        TestRecord testRecordOnFile = testRecordService.findById(Long.valueOf(testRecordID));
        testRecordService.updateTestRecord(Long.valueOf(testRecordID),
                testRecordOnFile.getUser().getId(), testRecord.getRecordName());
    }
}
