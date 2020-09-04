package com.springsecurity.weblogin.repositories;

import com.springsecurity.weblogin.model.TestRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;
import java.util.Set;

public interface TestRecordRepository extends JpaRepository<TestRecord, Long> {
    Optional<TestRecord> findByRecordName(String recordName);

    Set<TestRecord> findAllByUser_Username(String username);
}
