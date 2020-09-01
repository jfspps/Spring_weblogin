package com.springsecurity.weblogin.model.security;

//Multi-tenancy: each AdminUser is part of a group of AdminUsers, all of whom access one User account (i.e. one User object,
//in which the credentials and account status are stored)

import com.springsecurity.weblogin.model.BaseEntity;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToMany;
import java.util.Set;

@NoArgsConstructor
@Getter
@Setter
@Entity
public class AdminUser extends BaseEntity {

    private String adminUserName;

    @OneToMany(mappedBy = "adminUser", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    Set<User> users;
}
