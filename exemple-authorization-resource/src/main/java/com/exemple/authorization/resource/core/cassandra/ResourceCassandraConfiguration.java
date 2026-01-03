package com.exemple.authorization.resource.core.cassandra;

import java.io.File;
import java.io.FileNotFoundException;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ResourceUtils;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.CqlSessionBuilder;
import com.datastax.oss.driver.api.core.config.DriverConfigLoader;
import com.exemple.authorization.resource.core.ResourceConfigurationProperties;

@Configuration
public class ResourceCassandraConfiguration {

    private final File cassandraResource;

    public ResourceCassandraConfiguration(
            ResourceConfigurationProperties resourceProperties)
            throws FileNotFoundException {
        this.cassandraResource = ResourceUtils.getFile(resourceProperties.cassandra().resourceConfiguration());
    }

    @Bean
    public CqlSessionBuilder sessionBuilder() {

        var loader = DriverConfigLoader.fromFile(cassandraResource);

        return CqlSession.builder().withConfigLoader(loader)
                .addTypeCodecs(new Json3Codec());
    }

    @Bean
    public CqlSession session() {

        return sessionBuilder().build();
    }

}
