package com.springsecurity.weblogin.services.springDataJPA.security;

import com.springsecurity.weblogin.model.security.AdminUser;
import com.springsecurity.weblogin.model.security.TeacherUser;
import com.springsecurity.weblogin.repositories.security.AdminUserRepository;
import com.springsecurity.weblogin.repositories.security.TeacherUserRepository;
import com.springsecurity.weblogin.services.securityServices.AdminUserService;
import com.springsecurity.weblogin.services.securityServices.TeacherUserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
@Profile("SDjpa")
public class TeacherUserSDjpaService implements TeacherUserService {

    private final TeacherUserRepository teacherUserRepository;

    public TeacherUserSDjpaService(TeacherUserRepository adminUserRepository) {
        this.teacherUserRepository = adminUserRepository;
    }

    @Override
    public TeacherUser save(TeacherUser object) {
        return teacherUserRepository.save(object);
    }

    @Override
    public TeacherUser findById(Long aLong) {
        return teacherUserRepository.findById(aLong).orElse(null);
    }

    @Override
    public Set<TeacherUser> findAll() {
        Set<TeacherUser> adminUsers = new HashSet<>();
        adminUsers.addAll(teacherUserRepository.findAll());
        return adminUsers;
    }

    @Override
    public TeacherUser findByTeacherUserName(String username) {
        return teacherUserRepository.findByTeacherUserName(username).orElse(null);
    }

    @Override
    public void delete(TeacherUser objectT) {
        teacherUserRepository.delete(objectT);
    }

    @Override
    public void deleteById(Long aLong) {
        teacherUserRepository.deleteById(aLong);
    }
}
