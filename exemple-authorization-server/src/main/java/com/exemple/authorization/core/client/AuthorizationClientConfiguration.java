package com.exemple.authorization.core.client;

import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.retry.RetryNTimes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(basePackageClasses = AuthorizationClientConfiguration.class)
public class AuthorizationClientConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationClientConfiguration.class);

    private final String address;

    private final int sessionTimeout;

    private final int connectionTimeout;

    private final int retry;

    private final int sleepMsBetweenRetries;

    public AuthorizationClientConfiguration(@Value("${authorization.zookeeper.host}") String address,
            @Value("${authorization.zookeeper.sessionTimeout:30000}") int sessionTimeout,
            @Value("${authorization.zookeeper.connectionTimeout:10000}") int connectionTimeout,
            @Value("${authorization.zookeeper.retry:3}") int retry,
            @Value("${authorization.zookeeper.sleepMsBetweenRetries:1000}") int sleepMsBetweenRetries) {

        this.address = address;
        this.sessionTimeout = sessionTimeout;
        this.connectionTimeout = connectionTimeout;
        this.retry = retry;
        this.sleepMsBetweenRetries = sleepMsBetweenRetries;
    }

    @Bean(initMethod = "start", destroyMethod = "close")
    public CuratorFramework authorizationCuratorFramework() {

        CuratorFramework client = CuratorFrameworkFactory.newClient(address, sessionTimeout, connectionTimeout,
                new RetryNTimes(retry, sleepMsBetweenRetries));
        client.getConnectionStateListenable().addListener((c, state) -> LOG.debug("State changed to: {}", state));

        return client;

    }

    @Bean(destroyMethod = "close")
    public CuratorFramework authorizationClientCuratorFramework() {

        return authorizationCuratorFramework().usingNamespace("authorization");

    }

}
