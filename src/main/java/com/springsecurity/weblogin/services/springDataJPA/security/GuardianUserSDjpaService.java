package com.springsecurity.weblogin.services.springDataJPA.security;

import com.springsecurity.weblogin.model.security.GuardianUser;
import com.springsecurity.weblogin.model.security.TeacherUser;
import com.springsecurity.weblogin.repositories.security.GuardianUserRepository;
import com.springsecurity.weblogin.services.securityServices.GuardianUserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
@Profile("SDjpa")
public class GuardianUserSDjpaService implements GuardianUserService {

    private final GuardianUserRepository guardianUserRepository;

    public GuardianUserSDjpaService(GuardianUserRepository guardianUserRepository) {
        this.guardianUserRepository = guardianUserRepository;
    }

    @Override
    public GuardianUser save(GuardianUser object) {
        return guardianUserRepository.save(object);
    }

    @Override
    public GuardianUser findById(Long aLong) {
        return guardianUserRepository.findById(aLong).orElse(null);
    }

    @Override
    public Set<GuardianUser> findAll() {
        Set<GuardianUser> adminUsers = new HashSet<>();
        adminUsers.addAll(guardianUserRepository.findAll());
        return adminUsers;
    }

    @Override
    public GuardianUser findByGuardianUserName(String username) {
        return guardianUserRepository.findByGuardianUserName(username).orElse(null);
    }

    @Override
    public void delete(GuardianUser objectT) {
        guardianUserRepository.delete(objectT);
    }

    @Override
    public void deleteById(Long aLong) {
        guardianUserRepository.deleteById(aLong);
    }
}
