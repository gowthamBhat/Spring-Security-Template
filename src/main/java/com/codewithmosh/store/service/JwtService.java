package com.codewithmosh.store.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;

import static io.jsonwebtoken.Jwts.*;

@Service
public class JwtService {

    @Value("${spring.jwt.secret}")
    private String secret;

  public  String generateToekens(String email){

        final long tokenExpiration = 86400; //1 day

     return  builder().
                subject(email)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis()+1000* tokenExpiration))
                .signWith(Keys.hmacShaKeyFor(secret.getBytes())).compact();

    }
    public boolean verifyToken(String token) {
        try {
         Claims claims =  Jwts.parser()
                    .verifyWith(Keys.hmacShaKeyFor(secret.getBytes()))
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

           return claims.getExpiration().after(new Date());

        } catch (Exception e) {
            return false;
        }
    }
}
