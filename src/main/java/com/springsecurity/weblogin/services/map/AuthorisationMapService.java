package com.springsecurity.weblogin.services.map;

import com.springsecurity.weblogin.dbUserModel.Authorisation;
import com.springsecurity.weblogin.exceptions.NotFoundException;
import com.springsecurity.weblogin.services.dbUserServices.AuthorisationService;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;

@Slf4j
@Service
@NoArgsConstructor
@Profile("map")
public class AuthorisationMapService extends AbstractMapService<Authorisation, Long> implements AuthorisationService {

    @Override
    public Authorisation save(Authorisation object) {
        if (object != null) {
            return super.save(object);
        } else
            System.out.println("Empty object passed to Authorisation()");
        return null;
    }

    @Override
    public Authorisation findById(Long id) {
        Optional<Authorisation> optional = Optional.ofNullable(super.findById(id));
        if (optional.isEmpty()){
            throw new NotFoundException("Authorisation not found with ID: " + id);
        }
        return optional.get();
    }

    @Override
    public Set<Authorisation> findAll() {
        return super.findAll();
    }

    @Override
    public void delete(Authorisation objectT) {
        super.delete(objectT);
    }

    @Override
    public void deleteById(Long id) {
        super.deleteById(id);
    }
}
