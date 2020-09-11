package com.springsecurity.weblogin.model.security;

//Multi-tenancy: each AdminUser is part of a group of AdminUsers, all of whom access one User account (i.e. one User object,
//in which the credentials and account status are stored)

import com.springsecurity.weblogin.model.BaseEntity;
import lombok.*;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToMany;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Size;
import java.util.Set;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
public class GuardianUser extends BaseEntity {

    @Size(min = 1, max = 255)
    private String guardianUserName;

    @OneToMany(mappedBy = "guardianUser", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    Set<User> users;
}
