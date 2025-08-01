package com.codewithmosh.store.repositories;

import com.codewithmosh.store.entities.Role;
import com.codewithmosh.store.entities.RoleName;
import com.codewithmosh.store.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {

    Optional<User> findByEmail(String email);
}
