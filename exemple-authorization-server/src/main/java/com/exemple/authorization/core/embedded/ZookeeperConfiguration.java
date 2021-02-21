package com.exemple.authorization.core.embedded;

import org.apache.curator.test.TestingServer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnClass(TestingServer.class)
public class ZookeeperConfiguration {

    private final int port;

    public ZookeeperConfiguration(@Value("${zookeeper.embedded.port:-1}") int port) {
        this.port = port;
    }

    @Bean(initMethod = "start", destroyMethod = "stop")
    public TestingServer embeddedZookeeper() throws Exception {

        return new TestingServer(port, false);
    }

}
