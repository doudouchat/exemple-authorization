package com.exemple.authorization.core.authentication.provider;

import java.util.Map;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;

@Component
public class BackAuthenticationProvider extends DaoAuthenticationProvider {

    private final Map<String, UserDetails> users;

    public BackAuthenticationProvider() {

        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

        users = Map.of("admin",
                User.builder()
                        .username("admin")
                        .password("{bcrypt}" + passwordEncoder.encode("admin123"))
                        .authorities("ROLE_BACK")
                        .build());
    }

    @PostConstruct
    protected void init() {

        this.setUserDetailsService((String username) -> {

            UserDetails user = this.users.get(username);

            if (user == null) {

                throw new BadCredentialsException(username);
            }

            return User.withUserDetails(user).build();
        });
    }

    @Override
    public boolean supports(Class<?> authentication) {
        var authenticationContext = SecurityContextHolder.getContext().getAuthentication();
        return authenticationContext != null && authenticationContext.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).anyMatch("SCOPE_ROLE_BACK"::equals);
    }

}
