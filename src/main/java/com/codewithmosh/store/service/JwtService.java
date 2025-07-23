package com.codewithmosh.store.service;

import com.codewithmosh.store.entities.User;
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

  public  String generateTokens(User user){

        final long tokenExpiration = 86400; //1 day

     return  builder().
                subject(user.getId().toString())
                .claim("email",user.getEmail())
                .claim("name",user.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis()+1000* tokenExpiration))
                .signWith(Keys.hmacShaKeyFor(secret.getBytes())).compact();

    }
    public boolean verifyToken(String token) {
        try {
         Claims claims = getPayload(token);

           return claims.getExpiration().after(new Date());

        } catch (Exception e) {
            return false;
        }
    }

    private Claims getPayload(String token) {
        return Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(secret.getBytes()))
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Long getUserIdFromToken(String token){

      return  Long.valueOf(getPayload(token).getSubject());
    }
}
