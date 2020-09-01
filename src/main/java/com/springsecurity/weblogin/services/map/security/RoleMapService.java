package com.springsecurity.weblogin.services.map.security;

import com.springsecurity.weblogin.exceptions.NotFoundException;
import com.springsecurity.weblogin.model.security.Role;
import com.springsecurity.weblogin.services.securityServices.RoleService;
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
public class RoleMapService extends AbstractMapService<Role, Long> implements RoleService {

    @Override
    public Role save(Role object) {
        if (object != null) {
            return super.save(object);
        } else
            System.out.println("Cannot save null Roles");
        return null;
    }

    @Override
    public Role findById(Long id) {
        Optional<Role> optional = Optional.ofNullable(super.findById(id));
        if (optional.isEmpty()){
            throw new NotFoundException("Role not found with ID: " + id);
        }
        return optional.get();
    }

    @Override
    public Set<Role> findAll() {
        return super.findAll();
    }

    @Override
    public Role findByRoleName(String roleName) {
        return this.findAll()
                .stream()
                .filter(user -> user.getRoleName().equals(roleName))
                .findFirst()
                .orElse(null);
    }

    @Override
    public void delete(Role objectT) {
        super.delete(objectT);
    }

    @Override
    public void deleteById(Long id) {
        super.deleteById(id);
    }
}
