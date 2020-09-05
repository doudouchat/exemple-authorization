package com.exemple.authorization.core.embedded;

import java.util.Arrays;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.github.nosan.embedded.cassandra.EmbeddedCassandraFactory;
import com.github.nosan.embedded.cassandra.api.Cassandra;
import com.github.nosan.embedded.cassandra.api.connection.CassandraConnection;
import com.github.nosan.embedded.cassandra.api.connection.CqlSessionCassandraConnectionFactory;
import com.github.nosan.embedded.cassandra.api.cql.CqlDataSet;
import com.github.nosan.embedded.cassandra.artifact.Artifact;
import com.github.nosan.embedded.cassandra.commons.io.FileSystemResource;
import com.github.nosan.embedded.cassandra.commons.io.Resource;

@Configuration
@ConditionalOnProperty(value = { "port", "version" }, prefix = "authorization.embedded.cassandra")
public class CassandraConfiguration {

    private final int port;

    private final String version;

    private final Resource[] scripts;

    public CassandraConfiguration(@Value("${authorization.embedded.cassandra.port}") int port,
            @Value("${authorization.embedded.cassandra.version}") String version,
            @Value("${authorization.embedded.cassandra.scripts}") String... scripts) {
        this.port = port;
        this.version = version;
        this.scripts = Arrays.stream(scripts).map(FileSystemResource::new).toArray(Resource[]::new);
    }

    @Bean(initMethod = "start", destroyMethod = "stop")
    public Cassandra embeddedCassandra() {
        EmbeddedCassandraFactory cassandraFactory = new EmbeddedCassandraFactory();
        cassandraFactory.setArtifact(Artifact.ofVersion(version));
        cassandraFactory.setPort(port);
        cassandraFactory.getEnvironmentVariables().put("MAX_HEAP_SIZE", "64M");
        cassandraFactory.getEnvironmentVariables().put("HEAP_NEWSIZE", "12m");

        cassandraFactory.getConfigProperties().put("disk_failure_policy", "stop_paranoid");

        return cassandraFactory.create();
    }

    @PostConstruct
    public void initKeyspace() {

        CqlSessionCassandraConnectionFactory cassandraConnectionFactory = new CqlSessionCassandraConnectionFactory();

        try (CassandraConnection connection = cassandraConnectionFactory.create(embeddedCassandra())) {

            CqlDataSet.ofResources(scripts).forEachStatement(connection::execute);
        }
    }

}
