package com.springsecurity.weblogin.services;

import com.springsecurity.weblogin.model.TestRecord;

import java.util.Set;

public interface TestRecordService {
        TestRecord save(TestRecord object);

        TestRecord findById(Long id);

        Set<TestRecord> findAll();

        void delete(TestRecord objectT);

        void deleteById(Long id);
}
