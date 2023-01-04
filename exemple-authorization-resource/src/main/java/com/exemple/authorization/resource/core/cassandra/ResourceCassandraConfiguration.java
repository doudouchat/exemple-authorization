package com.exemple.authorization.resource.core.cassandra;

import java.io.File;
import java.io.FileNotFoundException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ResourceUtils;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.config.DriverConfigLoader;
import com.datastax.oss.driver.api.core.type.codec.ExtraTypeCodecs;
import com.fasterxml.jackson.databind.JsonNode;

@Configuration
public class ResourceCassandraConfiguration {

    private final File cassandraResource;

    public ResourceCassandraConfiguration(
            @Value("${authorization.resource.cassandra.resource_configuration}") String cassandraResource)
            throws FileNotFoundException {
        this.cassandraResource = ResourceUtils.getFile(cassandraResource);
    }

    @Bean
    public CqlSession session() {

        var loader = DriverConfigLoader.fromFile(cassandraResource);

        return CqlSession.builder().withConfigLoader(loader)
                .addTypeCodecs(ExtraTypeCodecs.json(JsonNode.class))
                .build();
    }

}
