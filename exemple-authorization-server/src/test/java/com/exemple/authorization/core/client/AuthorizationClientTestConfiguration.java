package com.exemple.authorization.core.client;

import org.apache.curator.test.TestingServer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.util.Assert;

@Configuration
@Import(AuthorizationClientConfiguration.class)
public class AuthorizationClientTestConfiguration {

    @Value("${authorization.zookeeper.port}")
    private int port;

    @Bean(destroyMethod = "close")
    public TestingServer embeddedZookeeper() throws Exception {

        Assert.isTrue(port != 0, "Port must be required");

        return new TestingServer(port, true);
    }

}
