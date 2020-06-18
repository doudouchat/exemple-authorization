package com.exemple.authorization.integration;

import org.apache.curator.test.TestingServer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

@SpringBootApplication
@EnableResourceServer
@ComponentScan("com.exemple.authorization.integration")
public class TestServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(TestServerApplication.class, args);
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
    public static class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
    }

    @Configuration
    public static class ZookeeperConfiguration {

        private final int port;

        public ZookeeperConfiguration(@Value("${test.embedded.zookeeper.port}") int port) {
            this.port = port;
        }

        @Bean(initMethod = "start", destroyMethod = "stop")
        public TestingServer embeddedZookeeper() throws Exception {

            return new TestingServer(port, false);
        }

    }

}
