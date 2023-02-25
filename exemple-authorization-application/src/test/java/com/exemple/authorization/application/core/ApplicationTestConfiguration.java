package com.exemple.authorization.application.core;

import org.apache.curator.test.TestingServer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import(ApplicationConfiguration.class)
public class ApplicationTestConfiguration {

    @Value("${application.zookeeper.port}")
    private int port;

    @Bean(destroyMethod = "stop")
    public TestingServer embeddedZookeeper() throws Exception {

        return new TestingServer(port, true);
    }
}
