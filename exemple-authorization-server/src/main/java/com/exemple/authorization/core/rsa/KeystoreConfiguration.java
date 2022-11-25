package com.exemple.authorization.core.rsa;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;

@Configuration
public class KeystoreConfiguration {

    private final RSAPublicKey publicKey;

    private final RSAPrivateKey privateKey;

    public KeystoreConfiguration(
            ResourceLoader resourceLoader,
            @Value("${authorization.certificat.location}") String certificateLocation,
            @Value("${authorization.certificat.alias}") String certificateAlias,
            @Value("${authorization.certificat.password}") String certificatePassword) throws IOException, GeneralSecurityException {

        var store = KeyStore.getInstance("jks");
        store.load(resourceLoader.getResource(certificateLocation).getInputStream(), certificatePassword.toCharArray());

        var key = (RSAPrivateCrtKey) store.getKey(certificateAlias, certificatePassword.toCharArray());
        var spec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());

        this.publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
        this.privateKey = key;

    }

    @Bean
    public RSAPublicKey publicKey() {
        return this.publicKey;
    }

    @Bean
    public RSAPrivateKey privateKey() {
        return this.privateKey;
    }

}
