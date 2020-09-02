package com.springsecurity.weblogin.web.controllers;

import com.springsecurity.weblogin.model.TestRecord;
import com.springsecurity.weblogin.services.TestRecordService;
import com.springsecurity.weblogin.web.permissionAnnot.GuardianRead;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;

import java.util.HashSet;
import java.util.Set;

@Controller
public class TestRecordController {

    private final TestRecordService testRecordService;

    public TestRecordController(TestRecordService testRecordService) {
        this.testRecordService = testRecordService;
    }

    //prevent the HTTP form POST from editing listed properties
    @InitBinder
    public void setAllowedFields(WebDataBinder dataBinder){
        dataBinder.setDisallowedFields("id");
    }

    @GuardianRead
    @GetMapping("/testRecord")
    public String getCRUDpage(Model model){
        Set<TestRecord> testRecords = new HashSet<>();
        testRecords.addAll(testRecordService.findAll());
        model.addAttribute("testRecords", testRecords);
        return "testRecord";
    }
}
