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

@Component
public class BackAuthenticationProvider extends DaoAuthenticationProvider {

    private static final Map<String, UserDetails> USERS;

    static {

        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        USERS = Map.of("admin",
                User.builder()
                        .username("admin")
                        .password("{bcrypt}" + passwordEncoder.encode("admin123"))
                        .authorities("ROLE_BACK")
                        .build());
    }

    public BackAuthenticationProvider() {

        super((String username) -> {
            UserDetails user = USERS.get(username);
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
