package com.exemple.authorization.common.security;

import java.security.Principal;
import java.util.Collection;

import javax.ws.rs.core.SecurityContext;

import org.springframework.security.oauth2.jwt.Jwt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class AuthorizationContextSecurity implements SecurityContext {

    private final Principal principal;

    private final Collection<String> roles;

    @Getter
    private final Jwt jwt;

    @Override
    public Principal getUserPrincipal() {
        return this.principal;
    }

    @Override
    public boolean isUserInRole(String role) {
        return roles.contains(role);
    }

    @Override
    public boolean isSecure() {
        return true;
    }

    @Override
    public String getAuthenticationScheme() {
        return SecurityContext.BASIC_AUTH;
    }

}
