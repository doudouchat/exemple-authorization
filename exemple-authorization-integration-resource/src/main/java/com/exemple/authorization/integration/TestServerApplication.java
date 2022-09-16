package com.exemple.authorization.integration;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan("com.exemple.authorization.integration")
public class TestServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(TestServerApplication.class, args);
    }

}
