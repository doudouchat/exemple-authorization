package com.exemple.authorization.core.authentication.provider;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class BackAuthenticationProvider extends DaoAuthenticationProvider {

    private Map<String, User> users = new HashMap<>();

    public BackAuthenticationProvider() {

        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

        users.put("admin", new User("admin", "{bcrypt}" + passwordEncoder.encode("admin123"),
                Arrays.stream(new String[] { "ROLE_BACK" }).map(SimpleGrantedAuthority::new).collect(Collectors.toList())));
    }

    @PostConstruct
    protected void init() {

        this.setUserDetailsService((String username) -> {

            User user = this.users.get(username);

            if (user == null) {

                throw new UsernameNotFoundException(username);
            }

            return user;
        });
    }

    @Override
    public boolean supports(Class<?> authentication) {

        return ((AbstractAuthenticationToken) SecurityContextHolder.getContext().getAuthentication()).getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).anyMatch("ROLE_BACK"::equals);
    }

}
