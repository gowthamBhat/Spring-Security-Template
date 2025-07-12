package com.codewithmosh.store.controller;

import com.codewithmosh.store.DTO.JwtResponse;
import com.codewithmosh.store.DTO.UserLoginRequestDTO;
import com.codewithmosh.store.entities.User;
import com.codewithmosh.store.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/user")
@AllArgsConstructor
public class UserController {

  private final UserService userService;


    @GetMapping
    ResponseEntity<Map<String,String>> AccessCheck(){

        return ResponseEntity.ok().body(Map.of("status","Access Passed"));
    }
    @GetMapping("/get-all")
    ResponseEntity<List<User>> listAlltheUsers(){

      List<User> users =   userService.getAlltheUsers();
        return ResponseEntity.ok().body(users);
    }




//    @PostMapping("/login")
//    ResponseEntity<?> userLoginHandler(@RequestBody UserLoginRequestDTO userDTO){
//     User user =   userService.getUserEmailid(userDTO.getEmail()).orElse(null);
//        if(user==null){
//            return ResponseEntity.badRequest().build();
//        }else{
//            return ResponseEntity.ok(user);
//        }
//
//    }

}
