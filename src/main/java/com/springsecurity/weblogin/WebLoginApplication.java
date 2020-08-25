package com.springsecurity.weblogin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

//note quite sure why I am having to component scan for repo's (this needs disabling when running dev profile)
@SpringBootApplication
public class WebLoginApplication {
    public static void main(String[] args) {
        SpringApplication.run(WebLoginApplication.class, args);
    }
}
