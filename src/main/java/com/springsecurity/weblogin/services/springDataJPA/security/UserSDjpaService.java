package com.springsecurity.weblogin.services.springDataJPA.security;

import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.repositories.security.UserRepository;
import com.springsecurity.weblogin.services.securityServices.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
@Profile("SDjpa")
public class UserSDjpaService implements UserService {

    private final UserRepository userRepository;

    public UserSDjpaService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public User save(User object) {
        return userRepository.save(object);
    }

    @Override
    public User findById(Long aLong) {
        return userRepository.findById(aLong).orElse(null);
    }

    @Override
    public Set<User> findAll() {
        Set<User> users = new HashSet<>();
        users.addAll(userRepository.findAll());
        return users;
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public void delete(User objectT) {
        userRepository.delete(objectT);
    }

    @Override
    public void deleteById(Long aLong) {
        userRepository.deleteById(aLong);
    }

}
