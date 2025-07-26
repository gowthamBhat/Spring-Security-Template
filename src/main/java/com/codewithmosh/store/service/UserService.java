package com.codewithmosh.store.service;

import com.codewithmosh.store.DTO.UserSIgnUpRequestDTO;
import com.codewithmosh.store.entities.Role;
import com.codewithmosh.store.entities.RoleName;
import com.codewithmosh.store.entities.User;
import com.codewithmosh.store.repositories.RoleRepository;
import com.codewithmosh.store.repositories.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@AllArgsConstructor
@Service
public class UserService {
    PasswordEncoder passwordEncoder;
    UserRepository userRepository;
    RoleRepository roleRepository;


    public User registerNewUser(UserSIgnUpRequestDTO request) {

        // Adding admin role shouldn't be in sign up logic, it should be kept separate for security reasons
        // by default all the users should get either USER or GUEST role

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        Set<Role> userRoles = new HashSet<>();
        if (request.getRoles() != null) {
            for (RoleName roleName : request.getRoles()) {
                Role role = roleRepository.findByName(roleName)
                        .orElseThrow(() -> new RuntimeException("Role not found: " + roleName));
                userRoles.add(role);
            }
        } else {
            // Assign default role
            Role defaultRole = roleRepository.findByName(RoleName.USER)
                    .orElseThrow(() -> new RuntimeException("Default role USER not found"));
            userRoles.add(defaultRole);
        }

        user.setRoles(userRoles);
        return userRepository.save(user);
    }



// public User saveUser(User user){
//   user.setPassword(passwordEncoder.encode(user.getPassword()));
//        return userRepository.save(user);
// }
    public Optional<User> findUserById(Long id){
     return userRepository.findById(id);
    }
    public List<User> getAlltheUsers() {
        return userRepository.findAll();
    }

    public Optional<User> getUserByEmailid(String email) {
     return userRepository.findByEmail(email);
    }
}
