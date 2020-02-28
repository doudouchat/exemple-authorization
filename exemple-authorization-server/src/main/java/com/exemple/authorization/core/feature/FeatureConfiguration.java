package com.exemple.authorization.core.feature;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;

import javax.ws.rs.ApplicationPath;

import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.glassfish.jersey.jackson.internal.jackson.jaxrs.json.JacksonJsonProvider;
import org.glassfish.jersey.logging.LoggingFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.serializer.JsonSerializer;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import com.auth0.jwt.algorithms.Algorithm;
import com.exemple.authorization.core.feature.authorization.AuthorizationFilter;
import com.exemple.authorization.password.properties.PasswordProperties;

@Configuration
@ApplicationPath("/ws")
@ComponentScan(basePackages = { "com.exemple.authorization.disconnection", "com.exemple.authorization.password" })
@EnableConfigurationProperties(PasswordProperties.class)
public class FeatureConfiguration extends ResourceConfig {

    public static final String APP_HEADER = "app";

    private final String bootstrapServers;

    private final String certificateLocation;

    private final String certificateAlias;

    private final String certificatePassword;

    public FeatureConfiguration(@Value("${authorization.kafka.bootstrap-servers}") String bootstrapServers,
            @Value("${authorization.certificat.location}") String certificateLocation,
            @Value("${authorization.certificat.alias}") String certificateAlias,
            @Value("${authorization.certificat.password}") String certificatePassword) {

        this.bootstrapServers = bootstrapServers;
        this.certificateLocation = certificateLocation;
        this.certificateAlias = certificateAlias;
        this.certificatePassword = certificatePassword;

        // Resources
        packages(
                // password feature
                "com.exemple.authorization.password",
                // disconnection feature
                "com.exemple.authorization.disconnection")

                        // security

                        .register(RolesAllowedDynamicFeature.class)

                        .register(AuthorizationFilter.class)

                        // logging

                        .register(LoggingFeature.class)

                        .property(LoggingFeature.LOGGING_FEATURE_VERBOSITY, LoggingFeature.Verbosity.PAYLOAD_ANY)

                        .property(LoggingFeature.LOGGING_FEATURE_LOGGER_LEVEL, Level.FINE.getName())

                        // JSON
                        .register(JacksonJsonProvider.class);

    }

    @Bean(destroyMethod = "reset")
    public DefaultKafkaProducerFactory<String, Map<String, Object>> producerFactory() {

        Map<String, Object> props = new HashMap<>();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);

        return new DefaultKafkaProducerFactory<>(props);
    }

    @Bean
    public KafkaTemplate<String, Map<String, Object>> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }

    @Bean
    public Algorithm algorithm(ResourceLoader resourceLoader) {

        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(resourceLoader.getResource(certificateLocation),
                certificatePassword.toCharArray());
        KeyPair keyPair = keyStoreKeyFactory.getKeyPair(certificateAlias);

        return Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());

    }

    @Bean
    public Clock clock() {
        return Clock.systemDefaultZone();
    }

}
