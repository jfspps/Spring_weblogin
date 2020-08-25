package com.springsecurity.weblogin.repositories;

import com.springsecurity.weblogin.dbUserModel.Authorisation;
import org.springframework.data.repository.CrudRepository;

public interface AuthorisationRepository extends CrudRepository<Authorisation, Long> {
    // add custom JPA queries here
}
