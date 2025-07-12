package com.codewithmosh.store.service;

import com.codewithmosh.store.entities.User;
import com.codewithmosh.store.repositories.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


import java.util.List;
import java.util.Optional;

@AllArgsConstructor
@Service
public class UserService {
    PasswordEncoder passwordEncoder;
    UserRepository userRepository;



 public User saveUser(User user){
   user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
 }

    public List<User> getAlltheUsers() {
        return userRepository.findAll();
    }

    public Optional<User> getUserEmailid(String email) {
     return userRepository.findByEmail(email);
    }
}
