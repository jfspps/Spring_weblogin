package com.springsecurity.weblogin.services.springDataJPA;

import com.springsecurity.weblogin.model.TestRecord;
import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.repositories.TestRecordRepository;
import com.springsecurity.weblogin.repositories.security.UserRepository;
import com.springsecurity.weblogin.services.TestRecordService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Slf4j
@Service
@Profile("SDjpa")
public class TestRecordSDjpaService implements TestRecordService {

    private final TestRecordRepository testRecordRepository;
    private final UserRepository userRepository;

    public TestRecordSDjpaService(TestRecordRepository testRecordRepository, UserRepository userRepository) {
        this.testRecordRepository = testRecordRepository;
        this.userRepository = userRepository;
    }

    @Override
    public TestRecord save(TestRecord object) {
        return testRecordRepository.save(object);
    }

    @Transactional
    @Override
    public TestRecord createTestRecord(String recordName, String username) {
        Optional<User> optionalUser = userRepository.findByUsername(username);
        if(optionalUser.isPresent()){
            TestRecord saved = testRecordRepository.save(TestRecord.builder().recordName(recordName).user(optionalUser.get()).build());

            //changes to user are cascaded to testRecords, so no need to save testRecords
            User savedUser = userRepository.saveAndFlush(optionalUser.get());
            log.debug("New testRecord with id: " + saved.getId() + " and name: " + saved.getRecordName() +
                    " associated with " + savedUser);
            return saved;
        }
        return null;
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
        testRecords.addAll(testRecordRepository.findAll());
        return testRecords;
    }

    @Override
    public TestRecord findByName(String recordName) {
        return testRecordRepository.findByRecordName(recordName).orElse(null);
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
