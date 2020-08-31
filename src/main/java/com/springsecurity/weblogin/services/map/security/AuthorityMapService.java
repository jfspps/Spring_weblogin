package com.springsecurity.weblogin.services.map.security;

import com.springsecurity.weblogin.exceptions.NotFoundException;
import com.springsecurity.weblogin.model.security.Authority;
import com.springsecurity.weblogin.services.securityServices.AuthorityService;
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
public class AuthorityMapService extends AbstractMapService<Authority, Long> implements AuthorityService {

    @Override
    public Authority save(Authority object) {
        if (object != null) {
            return super.save(object);
        } else
            System.out.println("Cannot save null Authorities");
        return null;
    }

    @Override
    public Authority findById(Long id) {
        Optional<Authority> optional = Optional.ofNullable(super.findById(id));
        if (optional.isEmpty()){
            throw new NotFoundException("Authority not found with ID: " + id);
        }
        return optional.get();
    }

    @Override
    public Set<Authority> findAll() {
        return super.findAll();
    }

    @Override
    public void delete(Authority objectT) {
        super.delete(objectT);
    }

    @Override
    public void deleteById(Long id) {
        super.deleteById(id);
    }
}
