package com.exemple.authorization.application.core;

import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.retry.RetryNTimes;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Configuration
@ComponentScan(basePackages = "com.exemple.authorization.application")
@RequiredArgsConstructor
@Slf4j
public class ApplicationConfiguration {

    @Value("${application.zookeeper.host}")
    private final String address;

    @Value("${application.zookeeper.sessionTimeout:30000}")
    private final int sessionTimeout;

    @Value("${application.zookeeper.connectionTimeout:10000}")
    private final int connectionTimeout;

    @Value("${application.zookeeper.retry:3}")
    private final int retry;

    @Value("${application.zookeeper.sleepMsBetweenRetries:1000}")
    private final int sleepMsBetweenRetries;

    @Bean(initMethod = "start", destroyMethod = "close")
    public CuratorFramework applicationCuratorFramework() {

        var client = CuratorFrameworkFactory.newClient(address, sessionTimeout, connectionTimeout, new RetryNTimes(retry, sleepMsBetweenRetries));

        client.getConnectionStateListenable().addListener((c, state) -> LOG.debug("State changed to: {}", state));

        return client;

    }

    @Bean(destroyMethod = "close")
    public CuratorFramework applicationDetailCuratorFramework() {

        return applicationCuratorFramework().usingNamespace("application");

    }

}
