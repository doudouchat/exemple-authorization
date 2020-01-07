package com.exemple.authorization.common.security;

import java.security.Principal;

import javax.ws.rs.core.SecurityContext;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.auth0.jwt.interfaces.Payload;

public class AuthorizationContextSecurity implements SecurityContext {

    private final OAuth2Authentication authentication;

    private final Payload payload;

    public AuthorizationContextSecurity(OAuth2Authentication authentication, Payload payload) {
        this.authentication = authentication;
        this.payload = payload;
    }

    @Override
    public Principal getUserPrincipal() {
        return () -> authentication.getPrincipal().toString();
    }

    @Override
    public boolean isUserInRole(String role) {
        return authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).anyMatch((String authority) -> authority.equals(role));
    }

    @Override
    public boolean isSecure() {
        return true;
    }

    @Override
    public String getAuthenticationScheme() {
        return SecurityContext.BASIC_AUTH;
    }

    public OAuth2Authentication getAuthentication() {
        return authentication;
    }

    public Payload getPayload() {
        return payload;
    }
}
