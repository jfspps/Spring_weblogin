package com.springsecurity.weblogin.services.springDataJPA.security;

import com.springsecurity.weblogin.model.security.Authority;
import com.springsecurity.weblogin.model.security.Role;
import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.repositories.security.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

//Role is intermediate of Users and Authorities: USER <--> ROLE <--> AUTHORITY

@ExtendWith(MockitoExtension.class)
class UserSDjpaServiceTest {

    @Mock
    UserRepository userRepositoryTEST;

    final String username = "someone";
    final String password = "weakPassword";
    Authority authority = Authority.builder().permission("allGame").build();
    Role role = Role.builder().roleName("ADMIN").authority(authority).build();
    User testUser;
    Set<User> userSet = new HashSet<>();
    Set<Role> roleSet = new HashSet<>();

    @InjectMocks
    UserSDjpaService userSDjpaService;

    @BeforeEach
    void setUp() {
        testUser = User.builder().username(username).password(password).role(role).build();
        userSet.add(testUser);
        roleSet.add(role);
    }

    @Test
    void save() {
        when(userRepositoryTEST.save(any())).thenReturn(testUser);

        User saved = userSDjpaService.save(User.builder().build());

        assertNotNull(saved);

        verify(userRepositoryTEST, times(1)).save(any());
    }

    @Test
    void findById() {
        when(userRepositoryTEST.findById(anyLong())).thenReturn(Optional.ofNullable(testUser));

        User found = userSDjpaService.findById(12L);

        assertNotNull(found);

        verify(userRepositoryTEST, times(1)).findById(anyLong());
    }

    @Test
    void findByUsername() {
        when(userRepositoryTEST.findByUsername(anyString())).thenReturn(Optional.ofNullable(testUser));

        User found = userSDjpaService.findByUsername("Jimmy");
        assertEquals(username, found.getUsername());

        verify(userRepositoryTEST, times(1)).findByUsername(anyString());
    }
}