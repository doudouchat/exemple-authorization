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

import lombok.RequiredArgsConstructor;

@Configuration
@ComponentScan(basePackageClasses = AuthorizationClientConfiguration.class)
@RequiredArgsConstructor
public class AuthorizationClientConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationClientConfiguration.class);

    @Value("${authorization.zookeeper.host}")
    private final String address;

    @Value("${authorization.zookeeper.sessionTimeout:30000}")
    private final int sessionTimeout;

    @Value("${authorization.zookeeper.connectionTimeout:10000}")
    private final int connectionTimeout;

    @Value("${authorization.zookeeper.retry:3}")
    private final int retry;

    @Value("${authorization.zookeeper.sleepMsBetweenRetries:1000}")
    private final int sleepMsBetweenRetries;

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
