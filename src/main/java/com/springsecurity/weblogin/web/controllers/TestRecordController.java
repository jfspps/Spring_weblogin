package com.springsecurity.weblogin.web.controllers;

import com.springsecurity.weblogin.services.TestRecordService;
import com.springsecurity.weblogin.web.permissionAnnot.GuardianRead;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;

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
    public String getCRUDpage(){
        return "testRecord";
    }
}
