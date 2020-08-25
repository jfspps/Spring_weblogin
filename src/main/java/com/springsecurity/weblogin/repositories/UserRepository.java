package com.springsecurity.weblogin.repositories;

import com.springsecurity.weblogin.dbUsers.User;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<User, Long>{
    // add custom JPA queries here
}
