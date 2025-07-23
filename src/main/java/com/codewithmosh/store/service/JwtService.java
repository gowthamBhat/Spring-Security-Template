package com.codewithmosh.store.service;

import com.codewithmosh.store.config.JwtConfig;
import com.codewithmosh.store.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;

import static io.jsonwebtoken.Jwts.*;

@AllArgsConstructor
@Service
public class JwtService {

    private final JwtConfig jwtConfig;

    public String generateAccessToken(User user) {
        return generateToken(user, jwtConfig.getAccessTokenExpiration());
    }

    public String generateRefereshToken(User user) {
        return generateToken(user, jwtConfig.getRefreshTokenEpiration());
    }

    //helper method to generate tokens
    private String generateToken(User user, long tokenExpiration) {
        return builder().
                subject(user.getId().toString())
                .claim("email", user.getEmail())
                .claim("name", user.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000 * tokenExpiration))
                .signWith(jwtConfig.getSecretKey()).compact();
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
}
