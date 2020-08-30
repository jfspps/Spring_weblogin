package com.springsecurity.weblogin.model.security;

import com.springsecurity.weblogin.model.BaseEntity;
import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
public class User extends BaseEntity {

    @NotNull
    @Size(min = 1, max = 255)
    private String username;

    @NotNull
    @Size(min = 8, max = 255)
    private String password;

    @Builder.Default
    private boolean enabled = true;

    @NotNull
    private String authority;

    //Singular (Lombok) builds a singular Set with one Authority in authorities
    @Singular
    @ManyToMany(cascade = CascadeType.MERGE)
    @JoinTable(name = "user_authority",
            joinColumns = {@JoinColumn(name = "USER_ID", referencedColumnName = "ID")},
            inverseJoinColumns = {@JoinColumn(name = "AUTHORITY_ID", referencedColumnName = "ID")})
    private Set<Authority> authorities;

    //adding other Spring's UserDetails interface properties

    //override the null value with true
    @Builder.Default
    private Boolean accountNonExpired = true;

    @Builder.Default
    private Boolean accountNonLocked = true;

    @Builder.Default
    private Boolean credentialsNonExpired = true;
}
