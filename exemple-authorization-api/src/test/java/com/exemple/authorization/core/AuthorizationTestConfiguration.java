package com.exemple.authorization.core;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.kafka.support.serializer.JsonDeserializer;
import org.springframework.kafka.test.EmbeddedKafkaBroker;
import org.springframework.kafka.test.EmbeddedKafkaZKBroker;

import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.exemple.authorization.core.feature.FeatureTestConfiguration;
import com.exemple.authorization.core.keyspace.ApiResourceKeyspace;
import com.exemple.authorization.resource.login.LoginResource;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import kafka.server.KafkaConfig;

@Configuration
@Import({ ApiConfiguration.class, FeatureTestConfiguration.class })
@ComponentScan(basePackageClasses = ApiResourceKeyspace.class)
@EnableAutoConfiguration
public class AuthorizationTestConfiguration {

    @Value("${authorization.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Value("${authorization.kafka.embedded.port}")
    private int kafkaPort;

    @Value("${authorization.kafka.embedded.dir}")
    private String logDir;

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
    @Primary
    public Clock fixedClock() {
        return Clock.fixed(Instant.now().truncatedTo(ChronoUnit.SECONDS), ZoneId.systemDefault());
    }

    @Bean
    public EmbeddedKafkaBroker embeddedKafka() {

        var embeddedKafka = new EmbeddedKafkaZKBroker(1, true, "new_password").brokerProperty(KafkaConfig.LogDirsProp(),
                logDir + "/" + UUID.randomUUID());
        embeddedKafka.kafkaPorts(kafkaPort);

        return embeddedKafka;
    }

    @Bean
    public Consumer<?, ?> consumerKafka() {

        Map<String, Object> configs = Map.of(
                ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers,
                ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class,
                ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class,
                ConsumerConfig.GROUP_ID_CONFIG, "test");
        return new KafkaConsumer<>(configs);

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

    @Bean("hazelcastClient")
    public HazelcastInstance client() {
        var config = Config.load();
        return Hazelcast.newHazelcastInstance(config);
    }
}
