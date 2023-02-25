package com.exemple.authorization.resource.core.cassandra;

import java.io.File;
import java.io.FileNotFoundException;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ResourceUtils;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.CqlSessionBuilder;
import com.datastax.oss.driver.api.core.config.DriverConfigLoader;
import com.datastax.oss.driver.api.core.type.codec.ExtraTypeCodecs;
import com.exemple.authorization.resource.core.ResourceConfigurationProperties;
import com.fasterxml.jackson.databind.JsonNode;

@Configuration
public class ResourceCassandraConfiguration {

    private final File cassandraResource;

    public ResourceCassandraConfiguration(
            ResourceConfigurationProperties resourceProperties)
            throws FileNotFoundException {
        this.cassandraResource = ResourceUtils.getFile(resourceProperties.getCassandra().getResourceConfiguration());
    }

    @Bean
    public CqlSessionBuilder sessionBuilder() {

        var loader = DriverConfigLoader.fromFile(cassandraResource);

        return CqlSession.builder().withConfigLoader(loader)
                .addTypeCodecs(ExtraTypeCodecs.json(JsonNode.class));
    }

    @Bean
    public CqlSession session() {

        return sessionBuilder().build();
    }

}
