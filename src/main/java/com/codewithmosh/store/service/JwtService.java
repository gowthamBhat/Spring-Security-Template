package com.codewithmosh.store.service;

import com.codewithmosh.store.config.JwtConfig;

import com.codewithmosh.store.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import lombok.AllArgsConstructor;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


import static io.jsonwebtoken.Jwts.*;

@AllArgsConstructor
@Service
public class JwtService {

    private final JwtConfig jwtConfig;

    public String generateAccessToken(User user) {
        return generateToken(user, jwtConfig.getAccessTokenExpiration());
    }

    public String generateRefreshToken(User user) {
        return generateToken(user, jwtConfig.getRefreshTokenEpiration());
    }

    //helper method to generate tokens
    private String generateToken(User user, long tokenExpiration) {
        Set<String> roleNames = user.getRoles().stream()
                .map(role -> role.getName().name()) // Extract enum name: USER, ADMIN
                .collect(Collectors.toSet());

        return builder()
                .subject(user.getId().toString())
                .claim("email", user.getEmail())
                .claim("name", user.getUsername())
                .claim("role", roleNames) //
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000 * tokenExpiration))
                .signWith(jwtConfig.getSecretKey())
                .compact();
    }

    public boolean verifyToken(String token) {
        try {
            Claims claims = getPayload(token);

            return claims.getExpiration().after(new Date());

        } catch (Exception e) {
            return false;
        }
    }

    //method to parse the received token and get the data out of it
    private Claims getPayload(String token) {
        return Jwts.parser()
                .verifyWith(jwtConfig.getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Long getUserIdFromToken(String token) {

        return Long.valueOf(getPayload(token).getSubject());
    }

    // getting user roles and map it to follow Authority token guidelines
    public Set<GrantedAuthority> getAuthoritiesFromToken(String token) {
        Claims claims = getPayload(token);

        Object rolesObj = claims.get("role");

        if (rolesObj instanceof List<?> roleList) {
            return roleList.stream()
                    .map(Object::toString)
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .collect(Collectors.toSet());
        }

        return Set.of();
    }


}
