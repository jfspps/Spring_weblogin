package com.springsecurity.weblogin.dbUserModel;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;

import javax.persistence.Entity;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "users")
@Entity
public class User extends BaseEntity {

    @NotNull
    @Size(min = 1, max = 255)
    private String username;

    @NotNull
    @Size(min = 8, max = 255)
    private String password;

    @NotNull
    private boolean enabled;

    @JsonIgnore
    @ManyToMany(mappedBy = "users")
    private Set<Authorisation> authorisations = new HashSet<>();

    @Builder
    public User(Long id, String username, String password, boolean enabled, Set<Authorisation> authorisations) {
        super(id);
        this.username = username;
        this.password = password;
        this.enabled = enabled;
        if (authorisations != null){
            this.authorisations = authorisations;
        }
    }
}
