package com.exemple.authorization.core.feature;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;

import javax.annotation.security.RolesAllowed;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.SecurityContext;

import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.support.serializer.JsonDeserializer;
import org.springframework.kafka.test.EmbeddedKafkaBroker;

import io.swagger.v3.oas.annotations.Hidden;
import kafka.server.KafkaConfig;

@Configuration
public class FeatureTestConfiguration extends FeatureConfiguration {

    @Value("${authorization.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Value("${authorization.kafka.embedded.port}")
    private int kafkaPort;

    @Value("${authorization.kafka.embedded.dir}")
    private String logDir;

    @Bean
    public Clock clock() {
        return Clock.fixed(super.clock().instant().truncatedTo(ChronoUnit.SECONDS), super.clock().getZone());
    }

    @Bean
    public EmbeddedKafkaBroker embeddedKafka() {

        EmbeddedKafkaBroker embeddedKafka = new EmbeddedKafkaBroker(1, true, "new_password").brokerProperty(KafkaConfig.LogDirsProp(),
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
    public TestApi testApi() {

        TestApi api = new TestApi();
        this.register(api);

        return api;

    }

    @Bean
    public TestFilter testFilter() {

        TestFilter filter = new TestFilter();
        this.register(filter);

        return filter;

    }

    @Path("/v1/test")
    @Hidden
    public static class TestApi {

        @GET
        @Produces(javax.ws.rs.core.MediaType.APPLICATION_JSON)
        @RolesAllowed("test:read")
        public javax.ws.rs.core.Response get() {

            return javax.ws.rs.core.Response.ok().build();

        }

    }

    public static class TestFilter implements ContainerRequestFilter {

        public SecurityContext context;

        @Override
        public void filter(ContainerRequestContext requestContext) {

            context = requestContext.getSecurityContext();

        }

    }

}
