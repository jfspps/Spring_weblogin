package com.springsecurity.weblogin.repositories.security;

import com.springsecurity.weblogin.model.security.TeacherUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TeacherUserRepository extends JpaRepository<TeacherUser, Long> {
}
