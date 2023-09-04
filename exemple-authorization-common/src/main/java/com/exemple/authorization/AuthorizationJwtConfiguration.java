package com.exemple.authorization;

import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import com.hazelcast.core.HazelcastInstance;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class AuthorizationJwtConfiguration {

    public static final String TOKEN_BLACK_LIST = "token.black_list";

    @Qualifier("hazelcastClient")
    private final HazelcastInstance client;

    @Bean
    public JwtDecoder decoder(RSAPublicKey publicKey) {

        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();

        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(Duration.ZERO),
                new TokenNotExcludedValidator()));

        return jwtDecoder;
    }

    @Bean
    public JWSSigner signer(PrivateKey privateKey) {

        return new RSASSASigner(privateKey);

    }

    private class TokenNotExcludedValidator implements OAuth2TokenValidator<Jwt> {

        @Override
        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            if (jwt.getId() != null && client.getMap(TOKEN_BLACK_LIST).containsKey(jwt.getId())) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("custom_code", jwt.getId() + " has been excluded", null));
            }
            return OAuth2TokenValidatorResult.success();
        }
    }

}
