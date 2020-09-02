package com.springsecurity.weblogin.repositories;

import com.springsecurity.weblogin.model.TestRecord;
import org.springframework.data.repository.CrudRepository;

public interface TestRecordRepository extends CrudRepository<TestRecord, Long> {
    TestRecord findByRecordName(String recordName);
}
