package com.exemple.authorization.core;

import java.time.Clock;
import java.util.Map;

import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.serializer.JacksonJsonSerializer;

import com.exemple.authorization.core.feature.FeatureConfiguration;
import com.exemple.authorization.core.keyspace.ApiResourceKeyspace;

import lombok.RequiredArgsConstructor;

@Configuration
@Import(FeatureConfiguration.class)
@ComponentScan(basePackageClasses = ApiResourceKeyspace.class)
@RequiredArgsConstructor
public class ApiConfiguration {

    @Value("${authorization.kafka.bootstrap-servers}")
    private final String bootstrapServers;

    @Bean(destroyMethod = "reset")
    public DefaultKafkaProducerFactory<String, Map<String, Object>> producerFactory() {

        Map<String, Object> props = Map.of(
                ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers,
                ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class,
                ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JacksonJsonSerializer.class);

        return new DefaultKafkaProducerFactory<>(props);
    }

    @Bean
    public KafkaTemplate<String, Map<String, Object>> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }

    @Bean
    public Clock clock() {
        return Clock.systemDefaultZone();
    }
}
