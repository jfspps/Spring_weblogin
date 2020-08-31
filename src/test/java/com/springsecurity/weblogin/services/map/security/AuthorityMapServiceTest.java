package com.springsecurity.weblogin.services.map.security;

import com.springsecurity.weblogin.exceptions.NotFoundException;
import com.springsecurity.weblogin.model.security.Authority;
import com.springsecurity.weblogin.model.security.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthorityMapServiceTest {

    AuthorityMapService authorityMapService;
    final String role = "KINGandQUEEN";
    User user = User.builder().build();
    Set<User> userSet = new HashSet<>();
    Authority testAuthority;

    @BeforeEach
    void setUp() {
        userSet.add(user);
        authorityMapService = new AuthorityMapService();
        testAuthority = authorityMapService.save(Authority.builder().role(role).users(userSet).build());
    }

    @Test
    void save() {
        assertEquals(role, testAuthority.getRole());
        System.out.println("testAuthority ID: " + testAuthority.getId());
    }

    @Test
    void findById() {
        Authority foundAuthority = authorityMapService.findById(1L);
        assertEquals(testAuthority.getId(), foundAuthority.getId());
    }

    @Test
    void findByIdNULL() {
        assertThrows(NotFoundException.class, () -> authorityMapService.findById(100L));
    }

    @Test
    void findAll() {
        assertEquals(1, authorityMapService.findAll().size());
    }

    @Test
    void delete() {
        authorityMapService.delete(authorityMapService.findById(1L));
        assertEquals(0, authorityMapService.findAll().size());
    }

    @Test
    void deleteById() {
        authorityMapService.deleteById(1L);
        assertEquals(0, authorityMapService.findAll().size());
    }
}