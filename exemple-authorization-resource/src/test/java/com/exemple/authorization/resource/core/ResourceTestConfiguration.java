package com.exemple.authorization.resource.core;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.ClassPathResource;

import com.datastax.oss.driver.api.core.CqlSession;
import com.exemple.authorization.resource.core.cassandra.ResourceCassandraConfiguration;
import com.github.nosan.embedded.cassandra.EmbeddedCassandraFactory;
import com.github.nosan.embedded.cassandra.api.Cassandra;
import com.github.nosan.embedded.cassandra.api.connection.CassandraConnection;
import com.github.nosan.embedded.cassandra.api.connection.CqlSessionCassandraConnectionFactory;
import com.github.nosan.embedded.cassandra.api.cql.CqlDataSet;
import com.github.nosan.embedded.cassandra.artifact.Artifact;

@Configuration
@Import(ResourceConfiguration.class)
public class ResourceTestConfiguration extends ResourceCassandraConfiguration {

    @Value("${authorization.resource.cassandra.port}")
    private int port;

    @Value("${authorization.resource.cassandra.version}")
    private String version;

    public ResourceTestConfiguration(@Value("${authorization.resource.cassandra.addresses}") String[] addresses,
            @Value("${authorization.resource.cassandra.port}") int port,
            @Value("${authorization.resource.cassandra.local_data_center}") String localDataCenter) {

        super(addresses, port, localDataCenter);
    }

    @Bean(initMethod = "start", destroyMethod = "stop")
    public Cassandra embeddedServer() {

        EmbeddedCassandraFactory cassandraFactory = new EmbeddedCassandraFactory();
        cassandraFactory.setArtifact(Artifact.ofVersion(version));
        cassandraFactory.setPort(port);
        cassandraFactory.getEnvironmentVariables().put("MAX_HEAP_SIZE", "64M");
        cassandraFactory.getEnvironmentVariables().put("HEAP_NEWSIZE", "12m");
        cassandraFactory.getConfigProperties().put("num_tokens", 1);
        cassandraFactory.getConfigProperties().put("initial_token", 0);
        cassandraFactory.getConfigProperties().put("hinted_handoff_enabled", false);

        return cassandraFactory.create();
    }

    @Bean
    public static PropertySourcesPlaceholderConfigurer propertyPlaceholderConfigurer() {

        PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer = new PropertySourcesPlaceholderConfigurer();

        YamlPropertiesFactoryBean properties = new YamlPropertiesFactoryBean();
        properties.setResources(new ClassPathResource("exemple-authorization-resource-test.yml"));

        propertySourcesPlaceholderConfigurer.setProperties(properties.getObject());
        return propertySourcesPlaceholderConfigurer;
    }

    @Bean
    @DependsOn("embeddedServer")
    public CqlSession session() {

        return super.session();
    }

    @PostConstruct
    public void initKeyspace() {

        CqlSessionCassandraConnectionFactory cassandraConnectionFactory = new CqlSessionCassandraConnectionFactory();

        try (CassandraConnection connection = cassandraConnectionFactory.create(embeddedServer())) {
            CqlDataSet.ofClasspaths("cassandra/keyspace.cql", "cassandra/test.cql", "cassandra/exec.cql").forEachStatement(connection::execute);
        }
    }

}
