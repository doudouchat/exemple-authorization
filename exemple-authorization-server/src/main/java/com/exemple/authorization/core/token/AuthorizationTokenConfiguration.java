package com.exemple.authorization.core.token;

import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import com.auth0.jwt.RegisteredClaims;
import com.hazelcast.core.HazelcastInstance;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

@Configuration
@ComponentScan("com.exemple.authorization.core.token")
public class AuthorizationTokenConfiguration {

    public static final String TOKEN_BLACK_LIST = "token.black_list";

    private final String alias;

    private final HazelcastInstance hazelcastInstance;

    private final KeyStoreKeyFactory keyStoreKeyFactory;

    public AuthorizationTokenConfiguration(ResourceLoader resourceLoader, @Qualifier("client") HazelcastInstance hazelcastInstance,
            @Value("${authorization.certificat.location}") String location, @Value("${authorization.certificat.alias}") String alias,
            @Value("${authorization.certificat.password}") String password) {

        this.alias = alias;
        this.hazelcastInstance = hazelcastInstance;
        this.keyStoreKeyFactory = new KeyStoreKeyFactory(resourceLoader.getResource(location), password.toCharArray());
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        var converter = new JwtAccessTokenConverter();
        converter.setKeyPair(this.keyStoreKeyFactory.getKeyPair(alias));
        converter.setJwtClaimsSetVerifier((Map<String, Object> claims) -> {

            Object jti = claims.get(RegisteredClaims.JWT_ID);
            if (jti != null && hazelcastInstance.getMap(TOKEN_BLACK_LIST).containsKey(jti.toString())) {
                throw new InvalidTokenException(jti + " has been excluded");
            }
        });
        return converter;
    }

    @Bean
    public TokenEnhancer tokenEnhancer() {

        var tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList((OAuth2AccessToken accessToken, OAuth2Authentication authentication) -> {

            Map<String, Object> additionalInfo = new HashMap<>();

            if (authentication.getPrincipal() instanceof User) {

                var user = (User) authentication.getPrincipal();
                additionalInfo.put("sub", user.getUsername());
            }
            additionalInfo.put("authorities",
                    authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));

            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);

            return accessToken;
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
        var builder = new RSAKey.Builder((RSAPublicKey) this.keyStoreKeyFactory.getKeyPair(alias).getPublic()).keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256).keyID("exemple-key-id");
        return new JWKSet(builder.build());
    }

}
