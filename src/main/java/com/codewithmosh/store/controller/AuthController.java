package com.codewithmosh.store.controller;

import com.codewithmosh.store.DTO.JwtResponse;
import com.codewithmosh.store.DTO.UserLoginRequestDTO;
import com.codewithmosh.store.DTO.UserSIgnUpRequestDTO;
import com.codewithmosh.store.config.JwtConfig;
import com.codewithmosh.store.entities.User;
import com.codewithmosh.store.service.JwtService;
import com.codewithmosh.store.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserService userService;
    private final JwtConfig jwtConfig;

    @GetMapping("/validate")
    public boolean checkAccess(@RequestHeader("Authorization") String authHeader) {
        String authToken = authHeader.replace("Bearer ", "");
        return jwtService.verifyToken(authToken);
    }

    @GetMapping("/currentuser")
    public ResponseEntity<?> currentLoggedInUser() {

        // we don't have to manually retrieve the auth header and decode the user details in it, every request passed through decurity filter
        // it is validated and decoded, valid requests data is stored in SecurityContextHolder object
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Long userId = (Long) authentication.getPrincipal();

        User user = userService.findUserById(userId).orElse(null);

        if (user == null) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> userLoginHandler(@RequestBody UserLoginRequestDTO userDTO, HttpServletResponse response) {
        System.out.println("email and password got from form:" + userDTO.getEmail() + " , " + userDTO.getPassword());
        try {
            // We use email as "username" here. If you use "username" field, change accordingly.
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            userDTO.getEmail(),  // principal
                            userDTO.getPassword() // credentials
                    )
            );
            User user = userService.getUserByEmailid(userDTO.getEmail()).orElseThrow();

            // If we reach here, authentication was successful!
            String token = jwtService.generateAccessToken(user);

            // now we need to send another token as a cookie, that can be used to refresh the token after expiration
            String refreshToken = jwtService.generateRefreshToken(user);
            Cookie cookie = new Cookie("refreshToken", refreshToken);

            // this makes it the cookie not accessible for JS in browser
            cookie.setHttpOnly(true);


            // route to send refresh token to, or an endpoint to refresh token
            cookie.setPath("/auth/refresh");

            cookie.setMaxAge(jwtConfig.getRefreshTokenEpiration());
            cookie.setSecure(true);

            // through response object we get low level control over the response
            response.addCookie(cookie);

            return ResponseEntity.ok(new JwtResponse(token));
        } catch (AuthenticationException e) {
            // Invalid credentials
            return ResponseEntity.status(401).body("Invalid email or password");
        }
    }

    @PostMapping("/refresh")
    ResponseEntity<JwtResponse>  refresh(@CookieValue(value = "refreshToken") String refreshToken){
          if(!jwtService.verifyToken(refreshToken)){
              return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
          }
          var userid = jwtService.getUserIdFromToken(refreshToken);
          var user = userService.findUserById(userid).orElseThrow();
          var accessToken = jwtService.generateAccessToken(user);

          return ResponseEntity.ok(new JwtResponse(accessToken));
    }


    @PostMapping("/signup")
    ResponseEntity<User> saveApplicationUser(@RequestBody UserSIgnUpRequestDTO user) {

        User userSaved = userService.registerNewUser(user);
        return ResponseEntity.ok().body(userSaved);
    }
}
