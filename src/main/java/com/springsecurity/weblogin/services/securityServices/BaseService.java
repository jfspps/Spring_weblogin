package com.springsecurity.weblogin.services.securityServices;

import java.util.Set;

public interface BaseService<T, ID> {

    T save(T object);

    T findById(ID id);

    Set<T> findAll();

    void delete(T objectT);

    void deleteById(ID id);
}
