package com.exemple.authorization.core.authentication.account;

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

        return User.builder()
                .username(username)
                .password(password)
                .authorities("ROLE_ACCOUNT")
                .disabled(disabled).accountLocked(accountLocked)
                .build();
    }
}
