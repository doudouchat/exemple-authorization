package com.exemple.authorization.core;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

@Configuration
@Import({ AuthorizationConfiguration.class,
        AuthenticationConfiguration.class,
        HazelcastHttpSessionConfiguration.class,
        AuthorizationClientTestConfiguration.class,
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
    public ApplicationDetailService ApplicationDetailService() {

        ApplicationDetailService service = Mockito.mock(ApplicationDetailService.class);

        ApplicationDetail detail = ApplicationDetail.builder()
                .keyspace("test")
                .clientId("clientId1")
                .build();

        Mockito.when(service.get(Mockito.anyString())).thenReturn(Optional.of(detail));

        return service;
    }
}
