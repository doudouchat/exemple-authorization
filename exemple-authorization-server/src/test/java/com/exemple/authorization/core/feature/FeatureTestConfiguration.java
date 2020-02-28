package com.exemple.authorization.core.feature;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.SecurityContext;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.test.EmbeddedKafkaBroker;

import kafka.server.KafkaConfig;

@Configuration
public class FeatureTestConfiguration extends FeatureConfiguration {

    @Value("${authorization.kafka.embedded.port}")
    private int kafkaPort;

    @Value("${authorization.kafka.embedded.dir}")
    private String logDir;

    public FeatureTestConfiguration(@Value("${authorization.kafka.bootstrap-servers}") String bootstrapServers,
            @Value("${authorization.certificat.location}") String certificateLocation,
            @Value("${authorization.certificat.alias}") String certificateAlias,
            @Value("${authorization.certificat.password}") String certificatePassword) {

        super(bootstrapServers, certificateLocation, certificateAlias, certificatePassword);

    }

    @Bean
    @Override
    public Clock clock() {
        return Clock.fixed(super.clock().instant().truncatedTo(ChronoUnit.SECONDS), super.clock().getZone());
    }

    @Bean
    public TestFilter testFilter() {

        TestFilter filter = new TestFilter();
        this.register(filter);

        return filter;

    }

    @Bean
    public EmbeddedKafkaBroker embeddedKafka() {

        EmbeddedKafkaBroker embeddedKafka = new EmbeddedKafkaBroker(1, true, "new_password").brokerProperty(KafkaConfig.LogDirsProp(),
                logDir + "/" + UUID.randomUUID());
        embeddedKafka.kafkaPorts(kafkaPort);

        return embeddedKafka;
    }

    public static class TestFilter implements ContainerRequestFilter {

        public SecurityContext context;

        @Override
        public void filter(ContainerRequestContext requestContext) {

            context = requestContext.getSecurityContext();

        }

    }

}
