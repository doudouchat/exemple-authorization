package com.exemple.authorization.core.token;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Map;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import com.hazelcast.core.HazelcastInstance;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import lombok.RequiredArgsConstructor;

@Configuration
@ComponentScan("com.exemple.authorization.core.token")
@RequiredArgsConstructor
public class AuthorizationTokenConfiguration {

    public static final String TOKEN_BLACK_LIST = "token.black_list";

    @Qualifier("client")
    private final HazelcastInstance hazelcastInstance;

    private final RSAPublicKey publicKey;

    private final RSAPrivateKey privateKey;

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        var converter = new JwtAccessTokenConverter();
        converter.setKeyPair(new KeyPair(publicKey, privateKey));
        converter.setJwtClaimsSetVerifier((Map<String, Object> claims) -> {

            Object jti = claims.get(JwtClaimNames.JTI);
            if (hazelcastInstance.getMap(TOKEN_BLACK_LIST).containsKey(jti.toString())) {
                throw new InvalidTokenException(jti + " has been excluded");
            }
        });
        return converter;
    }

    @Bean
    public TokenEnhancer tokenEnhancer() {

        var tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList((OAuth2AccessToken accessToken, OAuth2Authentication authentication) -> {

            var token = new DefaultOAuth2AccessToken(accessToken);
            if (authentication.getPrincipal() instanceof User user) {
                token.getAdditionalInformation().put("sub", user.getUsername());
            }
            token.getAdditionalInformation().put("authorities",
                    authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
            return token;
        }, accessTokenConverter()));

        return tokenEnhancerChain;

    }

    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        var defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setSupportRefreshToken(true);
        return defaultTokenServices;
    }

    @Bean
    public JWKSet jwkSet() {
        var builder = new RSAKey.Builder(publicKey)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256).keyID("exemple-key-id");
        return new JWKSet(builder.build());
    }

}
