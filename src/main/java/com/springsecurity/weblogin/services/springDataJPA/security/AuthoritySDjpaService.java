package com.springsecurity.weblogin.services.springDataJPA.security;

import com.springsecurity.weblogin.model.security.Authority;
import com.springsecurity.weblogin.repositories.security.AuthorityRepository;
import com.springsecurity.weblogin.services.securityServices.AuthorityService;

import java.util.HashSet;
import java.util.Set;

public class AuthoritySDjpaService implements AuthorityService {

    private final AuthorityRepository authorityRepository;

    public AuthoritySDjpaService(AuthorityRepository authorityRepository) {
        this.authorityRepository = authorityRepository;
    }

    @Override
    public Authority save(Authority object) {
        return authorityRepository.save(object);
    }

    @Override
    public Authority findById(Long aLong) {
        return authorityRepository.findById(aLong).orElse(null);
    }

    @Override
    public Set<Authority> findAll() {
        Set<Authority> authorities = new HashSet<>();
        authorities.addAll(authorityRepository.findAll());
        return authorities;
    }

    @Override
    public void delete(Authority objectT) {
        authorityRepository.delete(objectT);
    }

    @Override
    public void deleteById(Long aLong) {
        authorityRepository.deleteById(aLong);
    }
}
