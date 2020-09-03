package com.springsecurity.weblogin.repositories;

import com.springsecurity.weblogin.model.TestRecord;
import org.springframework.data.repository.CrudRepository;

import java.util.Set;

public interface TestRecordRepository extends CrudRepository<TestRecord, Long> {
    TestRecord findByRecordName(String recordName);

    Set<TestRecord> findAllByUser_Username(String username);
}
