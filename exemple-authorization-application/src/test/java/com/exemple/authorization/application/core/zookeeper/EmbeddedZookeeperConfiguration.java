package com.exemple.authorization.application.core.zookeeper;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableConfigurationProperties(EmbeddedZookeeperConfigurationProperties.class)
@RequiredArgsConstructor
@Slf4j
public class EmbeddedZookeeperConfiguration {

    private final EmbeddedZookeeperConfigurationProperties properties;

    @Bean
    public GenericContainer<?> embeddedZookeeper() {

        return new GenericContainer<>("zookeeper:" + properties.version())
                .withExposedPorts(2181)
                .withLogConsumer(new Slf4jLogConsumer(LOG));
    }

}
