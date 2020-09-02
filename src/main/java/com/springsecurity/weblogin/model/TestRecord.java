package com.springsecurity.weblogin.model;

//this class represents a sample database POJO to test user authentication and authorisation

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.Entity;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class TestRecord extends BaseEntity {

    private String recordName;
}
