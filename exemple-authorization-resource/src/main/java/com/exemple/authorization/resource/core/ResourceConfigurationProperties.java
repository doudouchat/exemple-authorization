package com.exemple.authorization.resource.core;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@ConfigurationProperties(prefix = "authorization.resource")
@RequiredArgsConstructor
@Getter
public class ResourceConfigurationProperties {

    private final Cassandra cassandra;

    @RequiredArgsConstructor
    @Getter
    public static class Cassandra {

        private final String resourceConfiguration;

    }

}
