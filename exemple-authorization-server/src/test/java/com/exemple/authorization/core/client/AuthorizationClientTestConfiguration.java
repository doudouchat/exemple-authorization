package com.exemple.authorization.core.client;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistrar;
import org.testcontainers.containers.GenericContainer;

import com.exemple.authorization.core.client.resource.AuthorizationClientResourceConfiguration;
import com.exemple.authorization.core.zookeeper.EmbeddedZookeeperConfiguration;

@Configuration
@Import({ AuthorizationClientResourceConfiguration.class, EmbeddedZookeeperConfiguration.class })
public class AuthorizationClientTestConfiguration {

    @Bean
    public DynamicPropertyRegistrar applicationProperties(GenericContainer<?> embeddedZookeeper) {
        return registry -> registry.add("authorization.zookeeper.host", () -> "127.0.0.1:" + embeddedZookeeper.getMappedPort(2181));
    }

}
