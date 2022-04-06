package com.exemple.authorization.common.security;

import java.security.Principal;
import java.util.Collections;
import java.util.Optional;

import javax.ws.rs.core.SecurityContext;

import org.apache.commons.lang3.ObjectUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.auth0.jwt.interfaces.Payload;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class AuthorizationContextSecurity implements SecurityContext {

    private final OAuth2Authentication authentication;

    private final Payload payload;

    @Override
    public Principal getUserPrincipal() {
        return () -> ObjectUtils.defaultIfNull(payload.getSubject(), authentication.getPrincipal().toString());
    }

    @Override
    public boolean isUserInRole(String role) {
        return authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).anyMatch((String authority) -> authority.equals(role))
                || Optional.ofNullable(payload.getClaim("scope").asList(String.class)).orElseGet(Collections::emptyList).stream()
                        .anyMatch((String scope) -> scope.equals(role));
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
