package com.springsecurity.weblogin.services.map.security;

import com.springsecurity.weblogin.exceptions.NotFoundException;
import com.springsecurity.weblogin.model.security.Authority;
import com.springsecurity.weblogin.model.security.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

//Role is intermediate of Users and Authorities: USER <--> ROLE <--> AUTHORITY

class AuthorityMapServiceTest {

    AuthorityMapService authorityMapService;
    RoleMapService roleMapService;
    final String permission = "fairGame";
    Role role = Role.builder().build();
    Set<Role> roleSet = new HashSet<>();
    Authority testAuthority;

    @BeforeEach
    void setUp() {
        roleSet.add(role);
        authorityMapService = new AuthorityMapService();
        roleMapService = new RoleMapService();
        testAuthority = authorityMapService.save(Authority.builder().roles(roleSet).permission(permission).build());
    }

    @Test
    void save() {
        assertEquals(roleSet, testAuthority.getRoles());
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