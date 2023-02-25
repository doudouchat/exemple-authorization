package com.exemple.authorization.resource.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ResourceUtils;
import org.testcontainers.shaded.org.apache.commons.io.FileUtils;

import com.datastax.oss.driver.api.core.CqlSession;

import jakarta.annotation.PostConstruct;

@Configuration
public class InitResourceTestConfiguration {

    @Autowired
    private CqlSession session;

    @PostConstruct
    void initKeyspace() throws IOException {

        session.setSchemaMetadataEnabled(false);

        executeScript("classpath:cassandra/keyspace.cql", session::execute);
        executeScript("classpath:cassandra/test.cql", session::execute);
        executeScript("classpath:cassandra/main.cql", session::execute);
        executeScript("classpath:cassandra/exec.cql", session::execute);

        session.setSchemaMetadataEnabled(true);
    }

    private static void executeScript(String resourceLocation, Consumer<String> execute) throws IOException {
        Stream.of(FileUtils.readFileToString(ResourceUtils.getFile(resourceLocation), StandardCharsets.UTF_8).trim().split(";"))
                .forEach(execute);
    }

}
