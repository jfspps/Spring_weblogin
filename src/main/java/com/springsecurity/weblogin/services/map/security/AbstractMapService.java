package com.springsecurity.weblogin.services.map.security;

import com.springsecurity.weblogin.model.BaseEntity;

import java.util.*;

public abstract class AbstractMapService<T extends BaseEntity, ID extends Long> {

    protected Map<Long, T> map = new HashMap<>();

    T save(T object) {
        if (object != null) {
            if (object.getId() == null) {
                object.setId(getNextId());
            }
            map.put(object.getId(), object);
        } else {
            throw new RuntimeException("Cannot save null objects");
        }

        return object;
    }

    T findById(ID id) {
        return map.get(id);
    }

    Set<T> findAll() {
        return new HashSet<>(map.values());
    }

    void delete(T objectT) {
        map.entrySet().removeIf(entry -> entry.getValue().equals(objectT));
    }

    void deleteById(ID id) {
        map.remove(id);
    }

    private Long getNextId() {
        if (map.isEmpty())
            return 1L;
        else
            return Collections.max(map.keySet()) + 1;
    }
}