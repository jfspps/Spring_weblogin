package com.springsecurity.weblogin.model;

//this class represents a sample database POJO to test user authentication and authorisation

import com.springsecurity.weblogin.model.security.User;
import lombok.*;

import javax.persistence.Entity;
import javax.persistence.ManyToOne;

@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TestRecord extends BaseEntity {

    private String recordName;

    @ManyToOne
    private User user;

    public TestRecord(String recordName) {
        this.recordName = recordName;
    }
}
