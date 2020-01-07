package com.exemple.authorization.core.authentication.provider;

import javax.annotation.PostConstruct;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.exemple.authorization.core.authentication.account.AccountDetailsService;

@Component
public class AccountAuthenticationProvider extends DaoAuthenticationProvider {

    private final AccountDetailsService accountDetailsService;

    public AccountAuthenticationProvider(AccountDetailsService accountDetailsService) {

        this.accountDetailsService = accountDetailsService;
    }

    @PostConstruct
    protected void init() {

        this.setUserDetailsService(accountDetailsService);
    }

    @Override
    public boolean supports(Class<?> authentication) {

        return ((AbstractAuthenticationToken) SecurityContextHolder.getContext().getAuthentication()).getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).anyMatch("ROLE_APP"::equals);
    }

}
