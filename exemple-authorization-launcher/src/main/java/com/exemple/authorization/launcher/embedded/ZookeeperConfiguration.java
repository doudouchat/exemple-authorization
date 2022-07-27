package com.exemple.authorization.launcher.embedded;

import org.apache.curator.test.TestingServer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.RequiredArgsConstructor;

@Configuration
@ConditionalOnClass(TestingServer.class)
@RequiredArgsConstructor
public class ZookeeperConfiguration {

    @Value("${zookeeper.embedded.port:-1}")
    private final int port;

    @Bean(initMethod = "start", destroyMethod = "stop")
    public TestingServer embeddedZookeeper() throws Exception {

        return new TestingServer(port, false);
    }

}
