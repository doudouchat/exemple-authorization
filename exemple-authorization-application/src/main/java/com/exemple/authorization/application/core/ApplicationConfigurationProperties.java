package com.exemple.authorization.application.core;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@ConfigurationProperties(prefix = "application")
@RequiredArgsConstructor
@Getter
public class ApplicationConfigurationProperties {

    private final Zookeeper zookeeper;

    @Getter
    public static class Zookeeper {

        private final String host;

        private final int sessionTimeout;

        private final int connectionTimeout;

        private final int retry;

        private final int sleepMsBetweenRetries;

        public Zookeeper(String host,
                @DefaultValue("30000") int sessionTimeout,
                @DefaultValue("10000") int connectionTimeout,
                @DefaultValue("3") int retry,
                @DefaultValue("1000") int sleepMsBetweenRetries) {
            this.host = host;
            this.sessionTimeout = sessionTimeout;
            this.connectionTimeout = connectionTimeout;
            this.sleepMsBetweenRetries = sleepMsBetweenRetries;
            this.retry = retry;
        }

    }

}
