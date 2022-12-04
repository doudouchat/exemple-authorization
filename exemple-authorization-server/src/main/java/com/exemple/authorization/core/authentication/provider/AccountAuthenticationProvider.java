package com.exemple.authorization.core.authentication.provider;

import javax.annotation.PostConstruct;

import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.exemple.authorization.core.authentication.account.AccountDetailsService;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AccountAuthenticationProvider extends DaoAuthenticationProvider {

    private final AccountDetailsService accountDetailsService;

    @PostConstruct
    protected void init() {

        this.setUserDetailsService(accountDetailsService);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        var authenticationContext = SecurityContextHolder.getContext().getAuthentication();
        return authenticationContext != null
                && authenticationContext.getAuthorities().stream().map(GrantedAuthority::getAuthority).anyMatch("SCOPE_ROLE_APP"::equals);
    }

}
