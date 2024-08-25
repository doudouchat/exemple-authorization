package com.exemple.authorization.resource.core.cassandra;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.testcontainers.cassandra.CassandraContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;

import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableConfigurationProperties(EmbeddedCassandraConfigurationProperties.class)
@Slf4j
public class EmbeddedCassandraConfiguration {

    @Bean
    public CassandraContainer embeddedServer(EmbeddedCassandraConfigurationProperties properties) {

        return new CassandraContainer("cassandra:" + properties.version())
                .withExposedPorts(9042)
                .waitingFor(Wait.forLogMessage(".*Startup complete.*\\n", 1))
                .withLogConsumer(new Slf4jLogConsumer(LOG));
    }

}
