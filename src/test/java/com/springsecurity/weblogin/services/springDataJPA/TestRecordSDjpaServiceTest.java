package com.springsecurity.weblogin.services.springDataJPA;

import com.springsecurity.weblogin.model.TestRecord;
import com.springsecurity.weblogin.repositories.TestRecordRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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

    private final String recordName = "example Record";
    TestRecord testRecord;
    Set<TestRecord> testRecords;

    @InjectMocks
    TestRecordSDjpaService testRecordSDjpaService;

    @BeforeEach
    void setUp() {
        testRecords = new HashSet<>();
        testRecord = new TestRecord();
        testRecord.setRecordName(recordName);
    }

    @Test
    void save() {
        when(testRecordRepository.save(any())).thenReturn(testRecord);

        TestRecord saved = testRecordSDjpaService.save(testRecord);
        assertNotNull(saved);

        verify(testRecordRepository, times(1)).save(any());
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
        testRecords.add(testRecord);
        when(testRecordRepository.findAll()).thenReturn(testRecords);

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