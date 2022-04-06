package com.exemple.authorization.core.authentication.account;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.exemple.authorization.resource.login.LoginResource;
import com.exemple.authorization.resource.login.model.LoginEntity;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AccountDetailsService implements UserDetailsService {

    private final LoginResource loginResource;

    @Override
    public UserDetails loadUserByUsername(String username) {

        LoginEntity login = loginResource.get(username).orElseThrow(() -> new UsernameNotFoundException(username));

        String password = login.getPassword();
        boolean disabled = login.isDisabled();
        boolean accountLocked = login.isAccountLocked();

        List<SimpleGrantedAuthority> roles = login.getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        return new User(username, password, !disabled, true, true, !accountLocked, roles);
    }
}
