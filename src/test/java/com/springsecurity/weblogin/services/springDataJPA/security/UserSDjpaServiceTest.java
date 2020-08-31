package com.springsecurity.weblogin.services.springDataJPA.security;

import com.springsecurity.weblogin.model.security.Authority;
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

@ExtendWith(MockitoExtension.class)
class UserSDjpaServiceTest {

    @Mock
    UserRepository userRepository;

    final String username = "someone";
    final String password = "weakPassword";
    Authority authority = Authority.builder().role("people").build();
    User testUser;
    Set<User> userSet = new HashSet<>();

    @InjectMocks
    UserSDjpaService userSDjpaService;

    @BeforeEach
    void setUp() {
        testUser = User.builder().username(username).password(password).authority(authority).build();
        userSet.add(testUser);
    }

    @Test
    void save() {
        when(userRepository.save(any())).thenReturn(testUser);

        User saved = userSDjpaService.save(User.builder().build());

        assertNotNull(saved);

        verify(userRepository, times(1)).save(any());
    }

    @Test
    void findById() {
        when(userRepository.findById(anyLong())).thenReturn(Optional.of(testUser));

        User found = userSDjpaService.findById(12L);

        assertNotNull(found);

        verify(userRepository, times(1)).findById(anyLong());
    }

    @Test
    void findByUsername() {
        when(userRepository.findByUsername(anyString())).thenReturn(testUser);

        User found = userSDjpaService.findByUsername("Jimmy");
        assertEquals(username, found.getUsername());

        verify(userRepository, times(1)).findByUsername(anyString());
    }
}