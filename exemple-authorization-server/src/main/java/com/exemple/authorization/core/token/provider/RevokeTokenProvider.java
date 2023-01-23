package com.exemple.authorization.core.token.provider;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.stereotype.Component;

import com.exemple.authorization.AuthorizationJwtConfiguration;
import com.exemple.authorization.core.token.AuthorizationOAuth2Repository;
import com.hazelcast.core.HazelcastInstance;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class RevokeTokenProvider implements AuthenticationProvider {

    private final HazelcastInstance client;

    private final AuthorizationOAuth2Repository authorizationService;

    @Override
    public Authentication authenticate(Authentication authentication) {

        var tokenValue = ((OAuth2TokenRevocationAuthenticationToken) authentication).getToken();

        authorizationService
                .findByToken(tokenValue)
                .map(oAuth2Authorization -> oAuth2Authorization.getToken(Jwt.class))
                .ifPresent(this::revokeToken);

        return new OAuth2TokenRevocationAuthenticationToken(tokenValue, authentication, null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2TokenRevocationAuthenticationToken.class.isAssignableFrom(authentication);
    }
    
    private void revokeToken(Token<Jwt> token) {
        
        if (token.getToken().getId() == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error("custom_code", "jti is missing", null));
        }

        if (token.getToken().getExpiresAt() == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error("custom_code", "exp is missing", null));
        }
        var start = Instant.now();
        var end = token.getToken().getExpiresAt();

        client.getMap(AuthorizationJwtConfiguration.TOKEN_BLACK_LIST)
                .put(token.getToken().getId(), start, ChronoUnit.SECONDS.between(start, end), TimeUnit.SECONDS);
    }

}
