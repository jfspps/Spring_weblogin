package com.springsecurity.weblogin.model.security;

import com.springsecurity.weblogin.model.BaseEntity;
import lombok.*;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import javax.transaction.Transactional;
import javax.validation.constraints.Size;
import java.util.Set;
import java.util.stream.Collectors;

//USER <--> ROLE <--> AUTHORITY

@Getter
@Setter
@AllArgsConstructor
@Builder
@NoArgsConstructor
@Entity
public class User extends BaseEntity implements UserDetails, CredentialsContainer {

    @Size(min = 1, max = 255)
    private String username;

    @Size(min = 8, max = 255)
    private String password;

    //Singular (Lombok) builds a singular Set with one Authority in authorities, called "authority"
    @Singular
//    Adding CascadeType.PERSIST is problematic for User
    @ManyToMany(cascade = {CascadeType.MERGE}, fetch = FetchType.EAGER)
    @JoinTable(name = "user_role",
            joinColumns = {@JoinColumn(name = "USER_ID", referencedColumnName = "ID")},
            inverseJoinColumns = {@JoinColumn(name = "ROLE_ID", referencedColumnName = "ID")})
    private Set<Role> roles;

    //recall from the DB as needed (when User is injected into the context, converting Authorities from Roles is handled here
    //instead of through JPAUserDetails (ensure roles is loaded eagerly, not lazily, above)
    @Transactional
    public Set<GrantedAuthority> getAuthorities() {
        return this.roles.stream()
                .map(Role::getAuthorities)
                .flatMap(Set::stream)
                .map(authority -> new SimpleGrantedAuthority(authority.getPermission()))
                .collect(Collectors.toSet());
    }

    //adding other Spring's UserDetails interface properties
    //override the null value with true
    @Builder.Default
    private Boolean enabled = true;

    @Builder.Default
    private Boolean accountNonExpired = true;

    @Builder.Default
    private Boolean accountNonLocked = true;

    @Builder.Default
    private Boolean credentialsNonExpired = true;

    //preparing for multi-tenancy (multiple User models with access to one account)
    @Override
    public void eraseCredentials() {
        this.password = null;
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    // account groups which are defined by a User: AdminUser

    @ManyToOne(fetch = FetchType.EAGER)
    private AdminUser adminUser;
}
