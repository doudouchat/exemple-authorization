package com.exemple.authorization.application.core;

import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.retry.RetryNTimes;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableConfigurationProperties(ApplicationConfigurationProperties.class)
@ComponentScan(basePackages = "com.exemple.authorization.application")
@RequiredArgsConstructor
@Slf4j
public class ApplicationConfiguration {

    private final ApplicationConfigurationProperties applicationProperties;

    @Bean(initMethod = "start", destroyMethod = "close")
    public CuratorFramework applicationCuratorFramework() {

        var client = CuratorFrameworkFactory.newClient(
                applicationProperties.getZookeeper().getHost(),
                applicationProperties.getZookeeper().getSessionTimeout(),
                applicationProperties.getZookeeper().getConnectionTimeout(),
                new RetryNTimes(applicationProperties.getZookeeper().getRetry(), applicationProperties.getZookeeper().getSleepMsBetweenRetries()));

        client.getConnectionStateListenable().addListener((c, state) -> LOG.debug("State changed to: {}", state));

        return client;

    }

    @Bean(destroyMethod = "close")
    public CuratorFramework applicationDetailCuratorFramework() {

        return applicationCuratorFramework().usingNamespace("application");

    }

}
