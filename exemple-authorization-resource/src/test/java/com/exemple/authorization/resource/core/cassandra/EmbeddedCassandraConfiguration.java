package com.exemple.authorization.resource.core.cassandra;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.testcontainers.containers.CassandraContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Testcontainers;

import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableConfigurationProperties(EmbeddedCassandraConfigurationProperties.class)
@Slf4j
@Testcontainers
public class EmbeddedCassandraConfiguration {

    @Bean
    @ServiceConnection
    public CassandraContainer<?> embeddedServer(EmbeddedCassandraConfigurationProperties properties) {

        return new CassandraContainer<>("cassandra:" + properties.version())
                .withExposedPorts(9042)
                .waitingFor(Wait.forLogMessage(".*Startup complete.*\\n", 1))
                .withLogConsumer(new Slf4jLogConsumer(LOG));
    }

}
