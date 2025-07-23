package com.codewithmosh.store.filters;

import com.codewithmosh.store.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


//this class will check for validation of headers, if the
@Component
@AllArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private JwtService jwtService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader =  request.getHeader("Authorization");
        // if the request not has token let it pass, and it will be caught in spring security validation next
        if(authHeader==null || !authHeader.startsWith("Bearer "))
        {
            filterChain.doFilter(request,response);
            return;
        }

        // if the request header is invalid or null, let it pass it will be caught in next spring validation
      String token =  authHeader.replace("Bearer ","");
        if(!jwtService.verifyToken(token)){
            filterChain.doFilter(request,response);
            return;
        }
    //if the request has reached here that means the request is valid and  has valid token in it


        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                jwtService.getUserIdFromToken(token),
                null,
                null
        );

        // adding aditional meta data
        authentication.setDetails(
              new WebAuthenticationDetailsSource().buildDetails(request)
        );

        // saving the user detail in Security context so it can be easily extracted later
        //it holds the authenticated user data
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request,response);
    }
}
