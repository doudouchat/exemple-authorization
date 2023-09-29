package com.exemple.authorization.resource.core;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.function.Consumer;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import com.datastax.oss.driver.api.core.CqlSession;

import jakarta.annotation.PostConstruct;

@Configuration
public class InitResourceTestConfiguration {

    @Autowired
    private CqlSession session;

    @PostConstruct
    void initKeyspace() throws IOException {

        session.setSchemaMetadataEnabled(false);

        executeScript(new ClassPathResource("cassandra/keyspace.cql"), session::execute);
        executeScript(new ClassPathResource("cassandra/test.cql"), session::execute);
        executeScript(new ClassPathResource("cassandra/main.cql"), session::execute);
        executeScript(new ClassPathResource("cassandra/exec.cql"), session::execute);

        session.setSchemaMetadataEnabled(true);
    }

    private static void executeScript(Resource script, Consumer<String> execute) throws IOException {
        Stream.of(script.getContentAsString(Charset.defaultCharset()).trim().split(";")).forEach(execute);
    }

}
