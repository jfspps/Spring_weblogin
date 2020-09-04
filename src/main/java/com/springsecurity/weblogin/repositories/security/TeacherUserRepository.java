package com.springsecurity.weblogin.repositories.security;

import com.springsecurity.weblogin.model.security.TeacherUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TeacherUserRepository extends JpaRepository<TeacherUser, Long> {
    Optional<TeacherUser> findByTeacherUserName(String username);
}
