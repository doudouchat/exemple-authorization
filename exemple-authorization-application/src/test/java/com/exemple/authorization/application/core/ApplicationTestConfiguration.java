package com.exemple.authorization.application.core;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistrar;
import org.testcontainers.containers.GenericContainer;

@Configuration
@Import(ApplicationConfiguration.class)
public class ApplicationTestConfiguration {

    @Bean
    public DynamicPropertyRegistrar applicationProperties(GenericContainer<?> embeddedZookeeper) {
        return registry -> registry.add("application.zookeeper.host", () -> "127.0.0.1:" + embeddedZookeeper.getMappedPort(2181));
    }
}
