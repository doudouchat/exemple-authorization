package com.exemple.authorization.core.client.resource;

import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.retry.RetryNTimes;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Configuration
@Import(AuthorizationClientResource.class)
@ComponentScan(basePackageClasses = AuthorizationClientResourceConfiguration.class)
@RequiredArgsConstructor
@Slf4j
public class AuthorizationClientResourceConfiguration {

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

        var client = CuratorFrameworkFactory.newClient(address, sessionTimeout, connectionTimeout, new RetryNTimes(retry, sleepMsBetweenRetries));
        client.getConnectionStateListenable().addListener((c, state) -> LOG.debug("State changed to: {}", state));

        return client;

    }

    @Bean(destroyMethod = "close")
    public CuratorFramework authorizationClientCuratorFramework() {

        return authorizationCuratorFramework().usingNamespace("authorization");

    }

}
