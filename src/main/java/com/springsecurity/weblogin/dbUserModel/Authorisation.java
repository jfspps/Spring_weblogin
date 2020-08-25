package com.springsecurity.weblogin.dbUserModel;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "authorisations")
@Entity
public class Authorisation extends BaseEntity {
    //Authority defines roles (ROLE_MEMBER, ROLE_ADMIN etc.)

    @JsonIgnore
    @JoinTable(name = "authorisation_user",
            joinColumns = @JoinColumn(name = "authorisation_id"), inverseJoinColumns = @JoinColumn(name = "user_id"))
    @ManyToMany
    private Set<User> users = new HashSet<>();

    @NotNull
    private String authority;

    @Builder
    public Authorisation(Long id, Set<User> users, String authority) {
        super(id);
        this.authority = authority;
        if (users != null){
            this.users = users;
        }
    }
}
