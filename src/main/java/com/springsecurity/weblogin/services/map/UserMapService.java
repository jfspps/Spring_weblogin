package com.springsecurity.weblogin.services.map;

import com.springsecurity.weblogin.dbUsers.User;
import com.springsecurity.weblogin.services.dbUserServices.UserService;
import com.springsecurity.weblogin.exceptions.NotFoundException;
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
public class UserMapService extends AbstractMapService<User, Long> implements UserService {

    @Override
    public User save(User object) {
        if (object != null) {
            return super.save(object);
        } else
            System.out.println("Empty object passed to User()");
        return null;
    }

    @Override
    public User findById(Long id) {
        Optional<User> optional = Optional.ofNullable(super.findById(id));
        if (optional.isEmpty()){
            throw new NotFoundException("User not found with ID: " + id);
        }
        return optional.get();
    }

    @Override
    public Set<User> findAll() {
        return super.findAll();
    }

    @Override
    public void delete(User objectT) {
        super.delete(objectT);
    }

    @Override
    public void deleteById(Long id) {
        super.deleteById(id);
    }
}
