package com.springsecurity.weblogin.services.springDataJPA.security;

import com.springsecurity.weblogin.model.security.AdminUser;
import com.springsecurity.weblogin.repositories.security.AdminUserRepository;
import com.springsecurity.weblogin.services.securityServices.AdminUserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
@Profile("SDjpa")
public class AdminUserSDjpaService implements AdminUserService {

    private final AdminUserRepository adminUserRepository;

    public AdminUserSDjpaService(AdminUserRepository adminUserRepository) {
        this.adminUserRepository = adminUserRepository;
    }

    @Override
    public AdminUser save(AdminUser object) {
        return adminUserRepository.save(object);
    }

    @Override
    public AdminUser findById(Long aLong) {
        return adminUserRepository.findById(aLong).orElse(null);
    }

    @Override
    public Set<AdminUser> findAll() {
        Set<AdminUser> adminUsers = new HashSet<>();
        adminUsers.addAll(adminUserRepository.findAll());
        return adminUsers;
    }

    @Override
    public void delete(AdminUser objectT) {
        adminUserRepository.delete(objectT);
    }

    @Override
    public void deleteById(Long aLong) {
        adminUserRepository.deleteById(aLong);
    }
}
