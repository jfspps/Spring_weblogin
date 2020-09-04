package com.springsecurity.weblogin.services.springDataJPA;

import com.springsecurity.weblogin.model.TestRecord;
import com.springsecurity.weblogin.model.security.User;
import com.springsecurity.weblogin.repositories.TestRecordRepository;
import com.springsecurity.weblogin.repositories.security.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TestRecordSDjpaServiceTest {

    @Mock
    TestRecordRepository testRecordRepository;

    @Mock
    UserRepository userRepository;

    TestRecord testRecord;
    Set<TestRecord> testRecords;

    @InjectMocks
    TestRecordSDjpaService testRecordSDjpaService;

    @BeforeEach
    void setUp() {
        testRecords = new HashSet<>();
        testRecord = new TestRecord();

        String recordName = "example Record";
        testRecord.setRecordName(recordName);
        testRecords.add(testRecord);
    }

    @Test
    void save() {
        when(testRecordRepository.save(any())).thenReturn(testRecord);

        TestRecord saved = testRecordSDjpaService.save(testRecord);
        assertNotNull(saved);

        verify(testRecordRepository, times(1)).save(any());
    }

    @Test
    void createTestRecord(){
        when(testRecordRepository.save(any())).thenReturn(TestRecord.builder().build());
        when(userRepository.saveAndFlush(any())).thenReturn(User.builder().build());
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(new User()));

        TestRecord created = testRecordSDjpaService.createTestRecord("recordName", "username");
        assertNotNull(created);
    }

    @Test
    void findById() {
        when(testRecordRepository.findById(anyLong())).thenReturn(Optional.of(testRecord));

        TestRecord found = testRecordSDjpaService.findById(76L);
        assertNotNull(found);

        verify(testRecordRepository, times(1)).findById(anyLong());
    }

    @Test
    void findAll() {
            when(testRecordRepository.findAll()).thenReturn(new ArrayList<>(testRecords));

            Set<TestRecord> recordsFound = testRecordSDjpaService.findAll();
            assertEquals(1, recordsFound.size());

            verify(testRecordRepository, times(1)).findAll();
    }

    @Test
    void deleteById() {
            Long id = testRecord.getId();
            testRecordSDjpaService.deleteById(id);
            assertEquals(0, testRecordRepository.count());
    }
}