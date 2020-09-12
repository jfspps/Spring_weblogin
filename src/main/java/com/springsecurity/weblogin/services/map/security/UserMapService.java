package com.springsecurity.weblogin.services.map.security;

import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.services.securityServices.UserService;
import com.springsecurity.weblogin.exceptions.NotFoundException;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

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
            System.out.println("Cannot save null Users");
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
    public User findByUsername(String username) {
        return this.findAll()
                .stream()
                .filter(user -> user.getUsername().equals(username))
                .findFirst()
                .orElse(null);
    }

    @Override
    public Set<User> findAllByUsername(String username) {
        return this.findAll()
                .stream()
                .filter(user -> user.getUsername().equals(username))
                .collect(Collectors.toSet());
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
