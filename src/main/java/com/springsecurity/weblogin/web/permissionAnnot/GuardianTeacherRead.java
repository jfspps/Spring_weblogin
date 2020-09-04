package com.springsecurity.weblogin.web.permissionAnnot;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasAnyAuthority('teacher.read', 'guardian.read')")
public @interface GuardianTeacherRead {
}

//this grants guardians to access their own test records (teachers, users and admin can see all records)