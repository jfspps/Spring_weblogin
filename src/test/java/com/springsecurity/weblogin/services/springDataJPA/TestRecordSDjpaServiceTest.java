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
    TestRecordRepository testRecordRepositoryTEST;

    @Mock
    UserRepository userRepository;

    TestRecord testRecord;
    User testUser;
    Set<TestRecord> testRecords;
    private final String recordName = "some record";
    private final String username = "someone";

    @InjectMocks
    TestRecordSDjpaService testRecordSDjpaService;

    @BeforeEach
    void setUp() {
        testRecords = new HashSet<>();
        testRecord = new TestRecord();
        testUser = User.builder().username(username).build();

        testRecord.setRecordName(recordName);
        testRecords.add(testRecord);
        testRecordRepositoryTEST.saveAndFlush(testRecord);
        testUser.setTestRecords(new HashSet<>(Set.of(testRecord)));
    }

    @Test
    void save() {
        when(testRecordRepositoryTEST.save(any())).thenReturn(testRecord);

        TestRecord saved = testRecordSDjpaService.save(testRecord);
        assertNotNull(saved);

        verify(testRecordRepositoryTEST, times(1)).save(any());
    }

    @Test
    void createTestRecord() {
        when(testRecordRepositoryTEST.save(any())).thenReturn(TestRecord.builder().build());
        when(userRepository.saveAndFlush(any())).thenReturn(User.builder().build());
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(new User()));

        TestRecord created = testRecordSDjpaService.createTestRecord("recordName", "username");
        assertNotNull(created);
    }

    @Test
    void updateTestRecord() {
        when(testRecordRepositoryTEST.findById(anyLong())).thenReturn(Optional.of(testRecord));
        when(userRepository.findById(anyLong())).thenReturn(Optional.of(testUser));
        when(userRepository.saveAndFlush(any())).thenReturn(testUser);

        TestRecord updated = testRecordSDjpaService.updateTestRecord(2L, 3L, "new name");
        assertNotNull(updated);
    }

    @Test
    void findById() {
        when(testRecordRepositoryTEST.findById(anyLong())).thenReturn(Optional.of(testRecord));

        TestRecord found = testRecordSDjpaService.findById(76L);
        assertNotNull(found);

        verify(testRecordRepositoryTEST, times(1)).findById(anyLong());
    }

    @Test
    void findAll() {
        when(testRecordRepositoryTEST.findAll()).thenReturn(new ArrayList<>(testRecords));

        Set<TestRecord> recordsFound = testRecordSDjpaService.findAll();
        assertEquals(1, recordsFound.size());

        verify(testRecordRepositoryTEST, times(1)).findAll();
    }

    @Test
    void deleteTestRecordAndUpdateUser(){
        when(testRecordRepositoryTEST.findById(anyLong())).thenReturn(Optional.ofNullable(testRecord));

        testRecordSDjpaService.deleteTestRecordAndUpdateUser(10L, testUser);

        verify(testRecordRepositoryTEST, times(1)).deleteById(anyLong());
    }
}