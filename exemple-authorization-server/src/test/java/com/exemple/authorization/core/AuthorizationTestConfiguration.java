package com.exemple.authorization.core;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.cassandra.CassandraAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.exemple.authorization.AuthorizationJwtConfiguration;
import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.exemple.authorization.core.authentication.AuthenticationConfiguration;
import com.exemple.authorization.core.client.AuthorizationClientTestConfiguration;
import com.exemple.authorization.core.session.HazelcastHttpSessionConfiguration;
import com.exemple.authorization.resource.login.LoginResource;
import com.exemple.authorization.resource.oauth2.OAuth2Resource;
import com.exemple.authorization.resource.oauth2.model.OAuth2Entity;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

@Configuration
@Import({
        AuthorizationClientTestConfiguration.class,
        AuthorizationConfiguration.class,
        AuthenticationConfiguration.class,
        HazelcastHttpSessionConfiguration.class,
        AuthorizationJwtConfiguration.class })
@EnableAutoConfiguration(exclude = CassandraAutoConfiguration.class)
public class AuthorizationTestConfiguration {

    public static final RSAKey RSA_KEY;

    static {

        try {
            RSA_KEY = new RSAKeyGenerator(2048).keyUse(KeyUse.SIGNATURE).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }

    }

    @Bean
    public RSAPublicKey publicKey() throws JOSEException {
        return RSA_KEY.toRSAPublicKey();
    }

    @Bean
    public RSAPrivateKey privateKey() throws JOSEException {
        return RSA_KEY.toRSAPrivateKey();
    }

    @Bean
    public LoginResource loginResource() {
        return Mockito.mock(LoginResource.class);
    }

    @Bean
    public OAuth2Resource OAuth2Resource() {
        Map<String, OAuth2Entity> authorizations = new ConcurrentHashMap<>();

        return new OAuth2Resource(null, null) {

            @Override
            public void save(OAuth2Entity oauth2) {
                authorizations.put(oauth2.getId(), oauth2);
            }

            @Override
            public Optional<OAuth2Entity> findByAuthorizationCodeValue(String token) {
                return authorizations.values().stream()
                        .filter(entity -> token.equals(entity.getAuthorizationCodeValue()))
                        .findAny();
            }

            @Override
            public Optional<OAuth2Entity> findByRefreshTokenValue(String token) {
                return authorizations.values().stream()
                        .filter(entity -> token.equals(entity.getRefreshTokenValue()))
                        .findAny();
            }
        };
    }

    @Bean
    public ApplicationDetailService ApplicationDetailService() {

        ApplicationDetailService service = Mockito.mock(ApplicationDetailService.class);

        ApplicationDetail detail = ApplicationDetail.builder()
                .keyspace("test")
                .clientId("clientId1")
                .build();

        Mockito.when(service.get(Mockito.anyString())).thenReturn(Optional.of(detail));

        return service;
    }

    @Bean("hazelcastClient")
    public HazelcastInstance client() {
        var config = Config.load();
        config.setClusterName("dev");
        return Hazelcast.newHazelcastInstance(config);
    }
}
