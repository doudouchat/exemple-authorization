package com.exemple.authorization.application.core;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "application")
public record ApplicationConfigurationProperties(Zookeeper zookeeper) {

    public static record Zookeeper(String host,
                                   @DefaultValue("30000") int sessionTimeout,
                                   @DefaultValue("10000") int connectionTimeout,
                                   @DefaultValue("3") int retry,
                                   @DefaultValue("1000") int sleepMsBetweenRetries) {

    }

}
