package com.springsecurity.weblogin.services.springDataJPA;

import com.springsecurity.weblogin.dbUserModel.Authorisation;
import com.springsecurity.weblogin.repositories.AuthorisationRepository;
import com.springsecurity.weblogin.services.dbUserServices.AuthorisationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
@Profile("springDataJPA")
public class AuthorisationSDjpaService implements AuthorisationService {

    private final AuthorisationRepository authorisationRepository;

    public AuthorisationSDjpaService(AuthorisationRepository authorisationRepository) {
        this.authorisationRepository = authorisationRepository;
    }

    @Override
    public Authorisation save(Authorisation object) {
        return authorisationRepository.save(object);
    }

    @Override
    public Authorisation findById(Long aLong) {
        return authorisationRepository.findById(aLong).orElse(null);
    }

    @Override
    public Set<Authorisation> findAll() {
        Set<Authorisation> authorisations = new HashSet<>();
        authorisationRepository.findAll().forEach(authorisations::add);
        return authorisations;
    }

    @Override
    public void delete(Authorisation objectT) {
        authorisationRepository.delete(objectT);
    }

    @Override
    public void deleteById(Long aLong) {
        authorisationRepository.deleteById(aLong);
    }
}
