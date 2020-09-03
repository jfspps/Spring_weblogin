package com.springsecurity.weblogin.services.springDataJPA;

import com.springsecurity.weblogin.model.TestRecord;
import com.springsecurity.weblogin.repositories.TestRecordRepository;
import com.springsecurity.weblogin.services.TestRecordService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
@Profile("SDjpa")
public class TestRecordSDjpaService implements TestRecordService {

    private TestRecordRepository testRecordRepository;

    public TestRecordSDjpaService(TestRecordRepository testRecordRepository) {
        this.testRecordRepository = testRecordRepository;
    }

    @Override
    public TestRecord save(TestRecord object) {
        return testRecordRepository.save(object);
    }

    @Override
    public TestRecord findById(Long id) {
        return testRecordRepository.findById(id).orElse(null);
    }

    @Override
    public Set<TestRecord> findAllTestRecordsByUsername(String username) {
        return testRecordRepository.findAllByUser_Username(username);
    }

    @Override
    public Set<TestRecord> findAll() {
        Set<TestRecord> testRecords = new HashSet<>();
        testRecordRepository.findAll().forEach(testRecords::add);
        return testRecords;
    }

    @Override
    public TestRecord findByName(String recordName) {
        return testRecordRepository.findByRecordName(recordName);
    }

    @Override
    public void delete(TestRecord objectT) {
        testRecordRepository.delete(objectT);
    }

    @Override
    public void deleteById(Long id) {
        testRecordRepository.deleteById(id);
    }
}
