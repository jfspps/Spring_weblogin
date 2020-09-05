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
            log.debug("New testRecord with id: " + saved.getId() + " and record name \"" + saved.getRecordName() +
                    "\" associated with " + savedUser.getUsername());
            return saved;
        }
        log.debug("Username: " + username + " not found");
        return null;
    }

    @Override
    @Transactional
    public TestRecord updateTestRecord(Long testRecordID, Long userID, String recordName) {
        if (testRecordRepository.findById(testRecordID).isEmpty() || userRepository.findById(userID).isEmpty()){
            log.debug("Required DB entries not found");
            return null;
        } else {
            TestRecord foundTestRecord = testRecordRepository.findById(testRecordID).get();
            foundTestRecord.setRecordName(recordName);
            User foundUser = userRepository.findById(userID).get();
            foundTestRecord.setUser(foundUser);
            userRepository.saveAndFlush(foundUser);
            log.debug("TestRecord with id: " + foundTestRecord.getId() + " associated to " + foundUser.getUsername() +
                    " updated to \"" + foundTestRecord.getRecordName() + "\"");
            return foundTestRecord;
        }
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
    public TestRecord findByRecordName(String recordName) {
        return testRecordRepository.findByRecordName(recordName).orElse(null);
    }

    @Override
    public void delete(TestRecord objectT) {
        testRecordRepository.delete(objectT);
        log.debug("TestRecord with id: " + objectT.getId() + " deleted");
    }

    @Override
    public void deleteById(Long id) {
        testRecordRepository.deleteById(id);
        log.debug("TestRecord with id: " + id + " deleted");
    }

    @Transactional
    @Override
    public void deleteTestRecordAndUpdateUser(Long testRecordID, User associatedUser) {
        if (testRecordRepository.findById(testRecordID).isPresent()){
            TestRecord temp = testRecordRepository.findById(testRecordID).get();
            log.debug("TestRecord with ID: " + temp.getId() + " and associated user ID: " + associatedUser.getId() + " found");
            if(associatedUser.getTestRecords().removeIf(aTestRecord -> aTestRecord.equals(temp))){
                log.debug("TestRecord removed from user account: " + associatedUser.getUsername());
                testRecordRepository.deleteById(testRecordID);
                log.debug("TestRecord \"" + temp.getRecordName() + "\" deleted from DB");
            }
        } else
            log.debug("No testRecord with ID: " + testRecordID + " found. No changes made.");
    }
}
