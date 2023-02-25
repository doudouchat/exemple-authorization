package com.exemple.authorization.resource.core;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.testcontainers.containers.CassandraContainer;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.CqlSessionBuilder;
import com.exemple.authorization.resource.core.cassandra.EmbeddedCassandraConfiguration;

@Configuration
@Import({ ResourceConfiguration.class, EmbeddedCassandraConfiguration.class })
public class ResourceTestConfiguration {

    @Autowired
    private CassandraContainer<?> cassandraContainer;

    @Bean
    @Primary
    public CqlSession session(CqlSessionBuilder sessionBuilder) {

        return sessionBuilder
                .addContactPoint(cassandraContainer.getContactPoint())
                .withLocalDatacenter(cassandraContainer.getLocalDatacenter())
                .build();
    }

}
