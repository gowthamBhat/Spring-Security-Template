package com.codewithmosh.store.config;

import com.codewithmosh.store.filters.JwtAuthenticationFilter;
import com.codewithmosh.store.service.UserAuthHelper;
import com.codewithmosh.store.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@AllArgsConstructor
@Configuration
public class SecurityConfig {
    private final UserAuthHelper userAuthService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    //  java prebuilt BCrypt class to encode classes
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(UserAuthHelper userAuthService, PasswordEncoder encoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userAuthService);
        provider.setPasswordEncoder(encoder);
        return provider;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // Disable CSRF protection as this is a stateless API (commonly used with JWT, not browser logins)
        http.csrf(csrf -> csrf.disable());

        // Configure session management as stateless - Spring Security will not create or use an HttpSession
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // Allow specific HTTP requests without authentication or authorization checks
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/auth/signup", "/auth/login", "/user/get-all", "/user").permitAll() // public endpoints
                        .anyRequest().authenticated() // everything else requires authentication
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        //adding custom filter and configuring it to execute first in order

        return http.build();
    }
}
