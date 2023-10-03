package com.exemple.authorization.resource.core;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "authorization.resource")
public record ResourceConfigurationProperties(Cassandra cassandra) {

    public static record Cassandra(String resourceConfiguration) {

    }

}
