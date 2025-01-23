package com.exemple.authorization.core.authentication.provider;

import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.exemple.authorization.core.authentication.account.AccountDetailsService;

@Component
public class AccountAuthenticationProvider extends DaoAuthenticationProvider {

    public AccountAuthenticationProvider(AccountDetailsService accountDetailsService) {
        super(accountDetailsService);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        var authenticationContext = SecurityContextHolder.getContext().getAuthentication();
        return authenticationContext != null
                && authenticationContext.getAuthorities().stream().map(GrantedAuthority::getAuthority).anyMatch("SCOPE_ROLE_APP"::equals);
    }

}
