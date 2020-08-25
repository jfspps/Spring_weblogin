package com.springsecurity.weblogin.dbUsers;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.Entity;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Getter
@Setter
@NoArgsConstructor
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

    @NotNull
    private String authorisation;

    @Builder
    public User(Long id, String username, String password, boolean enabled, String authorisation) {
        super(id);
        this.username = username;
        this.password = password;
        this.enabled = enabled;
        this.authorisation = authorisation;
    }
}
