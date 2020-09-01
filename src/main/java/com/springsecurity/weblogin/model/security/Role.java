package com.springsecurity.weblogin.model.security;

//Role is intermediate of Users and Authorities: USER <--> ROLE <--> AUTHORITY

import com.springsecurity.weblogin.model.BaseEntity;
import lombok.*;

import javax.persistence.*;
import java.util.Set;

//USER <--> ROLE <--> AUTHORITY

@Getter
@Setter
@AllArgsConstructor
@Builder
@NoArgsConstructor
@Entity
public class Role extends BaseEntity {

    private String name;

    @ManyToMany(mappedBy = "roles")
    private Set<User> users;

    @Singular
    @ManyToMany(cascade = {CascadeType.MERGE, CascadeType.PERSIST}, fetch = FetchType.EAGER)
    @JoinTable(name = "role_authority",
            joinColumns = {@JoinColumn(name = "ROLE_ID", referencedColumnName = "ID")},
            inverseJoinColumns = {@JoinColumn(name = "AUTHORITY_ID", referencedColumnName = "ID")})
    private Set<Authority> authorities;
}
