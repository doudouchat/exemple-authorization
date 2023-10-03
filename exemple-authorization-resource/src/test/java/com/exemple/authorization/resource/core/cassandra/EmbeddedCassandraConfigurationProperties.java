package com.exemple.authorization.resource.core.cassandra;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "authorization.resource.cassandra")
public record EmbeddedCassandraConfigurationProperties(String version) {
}
