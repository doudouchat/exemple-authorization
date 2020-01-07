package com.exemple.authorization.core.token;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ResourceLoader;
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

import com.auth0.jwt.impl.PublicClaims;
import com.hazelcast.core.HazelcastInstance;

@Configuration
public class AuthorizationTokenConfiguration {

    public static final String TOKEN_BLACK_LIST = "token.black_list";

    @Value("${authorization.certificat.location}")
    private String location;

    @Value("${authorization.certificat.alias}")
    private String alias;

    @Value("${authorization.certificat.password}")
    private String password;

    private final ResourceLoader resourceLoader;

    private final HazelcastInstance hazelcastInstance;

    public AuthorizationTokenConfiguration(ResourceLoader resourceLoader, HazelcastInstance hazelcastInstance) {
        this.resourceLoader = resourceLoader;
        this.hazelcastInstance = hazelcastInstance;
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(resourceLoader.getResource(location), password.toCharArray());
        converter.setKeyPair(keyStoreKeyFactory.getKeyPair(alias));
        converter.setJwtClaimsSetVerifier((Map<String, Object> claims) -> {

            Object jti = claims.get(PublicClaims.JWT_ID);
            if (jti != null && hazelcastInstance.getMap(TOKEN_BLACK_LIST).containsKey(jti.toString())) {
                throw new InvalidTokenException(jti + " has been excluded");
            }
        });
        return converter;
    }

    @Bean
    public TokenEnhancer tokenEnhancer() {

        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList((OAuth2AccessToken accessToken, OAuth2Authentication authentication) -> {

            Map<String, Object> additionalInfo = new HashMap<>();

            if (authentication.getPrincipal() instanceof User) {

                User user = (User) authentication.getPrincipal();
                additionalInfo.put("sub", user.getUsername());
            }

            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);

            return accessToken;
        }, accessTokenConverter()));

        return tokenEnhancerChain;

    }

    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setSupportRefreshToken(true);
        return defaultTokenServices;
    }

}
