package com.exemple.authorization.core.feature.authorization;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import com.hazelcast.core.HazelcastInstance;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;

@Configuration
public class AuthorizationFeatureConfiguration {

    public static final String TOKEN_BLACK_LIST = "token.black_list";

    private RSAPublicKey publicKey;

    private RSAPrivateKey privateKey;

    private final HazelcastInstance hazelcastInstance;

    public AuthorizationFeatureConfiguration(
            ResourceLoader resourceLoader,
            HazelcastInstance hazelcastInstance,
            @Value("${authorization.certificat.location}") String certificateLocation,
            @Value("${authorization.certificat.alias}") String certificateAlias,
            @Value("${authorization.certificat.password}") String certificatePassword) {

        this.hazelcastInstance = hazelcastInstance;

        var keyStoreKeyFactory = new KeyStoreKeyFactory(resourceLoader.getResource(certificateLocation), certificatePassword.toCharArray());
        var keyPair = keyStoreKeyFactory.getKeyPair(certificateAlias);

        this.publicKey = (RSAPublicKey) keyPair.getPublic();
        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();

    }

    @Bean
    public JwtDecoder decoder() {

        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();

        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(Duration.ZERO),
                new TokenNotExcludedValidator()));

        return jwtDecoder;
    }

    @Bean
    public JWSSigner signer() {

        return new RSASSASigner(privateKey);

    }

    private class TokenNotExcludedValidator implements OAuth2TokenValidator<Jwt> {

        @Override
        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            if (hazelcastInstance.getMap(TOKEN_BLACK_LIST).containsKey(jwt.getId())) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("custom_code", jwt.getId() + " has been excluded", null));
            }
            return OAuth2TokenValidatorResult.success();
        }
    }

}
