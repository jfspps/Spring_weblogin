package com.springsecurity.weblogin.services.map.security;

import com.springsecurity.weblogin.exceptions.NotFoundException;
import com.springsecurity.weblogin.model.security.Authority;
import com.springsecurity.weblogin.model.security.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UserMapServiceTest {

    UserMapService userMapService;
    final String username = "someone";
    final String password = "weakPassword";
    Authority authority = Authority.builder().role("people").build();
    User testUser;

    @BeforeEach
    void setUp() {
        userMapService = new UserMapService();
        testUser = userMapService.save(User.builder().username(username).password(password).authority(authority).build());
    }

    @Test
    void save() {
        assertEquals(username, testUser.getUsername());
        System.out.println("testUser ID: " + testUser.getId());
    }

    @Test
    void findById() {
        User foundUser = userMapService.findById(1L);
        assertEquals(testUser.getId(), foundUser.getId());
    }

    @Test
    void findByIdNULL() {
        assertThrows(NotFoundException.class, () -> userMapService.findById(100L));
    }

    @Test
    void findAll() {
        assertEquals(1, userMapService.findAll().size());
    }

    @Test
    void findByUsername() {
        User found = userMapService.findByUsername(username);
        assertEquals(username, found.getUsername());
    }

    @Test
    void findByUsernameNULL(){
        User found = userMapService.findByUsername("unknown");
        assertNull(found);
    }


    @Test
    void delete() {
        userMapService.delete(userMapService.findById(1L));
        assertEquals(0, userMapService.findAll().size());
    }

    @Test
    void deleteById() {
        userMapService.deleteById(1L);
        assertEquals(0, userMapService.findAll().size());
    }
}