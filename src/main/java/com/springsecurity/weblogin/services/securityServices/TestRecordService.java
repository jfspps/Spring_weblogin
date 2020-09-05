package com.springsecurity.weblogin.services.securityServices;

import com.springsecurity.weblogin.model.TestRecord;

public interface TestRecordService extends BaseService<TestRecord, Long>{
    TestRecord findAllTestRecordsByUsername(String username);

    TestRecord createTestRecord(String recordName, String username);

    TestRecord updateTestRecord(Long testRecordID, Long userID, String recordName);

    void deleteTestRecordAndUpdateUser(Long testRecordID);
}
