package com.codewithmosh.store.repositories;

import com.codewithmosh.store.entities.Role;
import com.codewithmosh.store.entities.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role,Long> {
    Optional<Role> findByName(RoleName name);
}
