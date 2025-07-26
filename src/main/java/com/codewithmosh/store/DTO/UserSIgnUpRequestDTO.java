package com.codewithmosh.store.DTO;

import com.codewithmosh.store.entities.RoleName;
import jakarta.persistence.Column;
import lombok.Data;

import java.util.Set;

@Data
public class UserSIgnUpRequestDTO {

    private String username;
    private String email;
    private String password;
    private Set<RoleName> roles;
}
