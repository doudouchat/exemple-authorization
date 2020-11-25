package com.exemple.authorization.resource.core;

import java.io.FileNotFoundException;

import javax.annotation.PostConstruct;

import org.slf4j.LoggerFactory;
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
import com.github.nosan.embedded.cassandra.Cassandra;
import com.github.nosan.embedded.cassandra.CassandraBuilder;
import com.github.nosan.embedded.cassandra.commons.logging.Slf4jLogger;
import com.github.nosan.embedded.cassandra.cql.CqlScript;

@Configuration
@Import(ResourceConfiguration.class)
public class ResourceTestConfiguration extends ResourceCassandraConfiguration {

    @Value("${authorization.resource.cassandra.port}")
    private int port;

    @Value("${authorization.resource.cassandra.version}")
    private String version;

    public ResourceTestConfiguration(@Value("${authorization.resource.cassandra.resource_configuration}") String cassandraResource)
            throws FileNotFoundException {

        super(cassandraResource);
    }

    @Bean(initMethod = "start", destroyMethod = "stop")
    public Cassandra embeddedServer() {

        return new CassandraBuilder()

                .version(version)

                .addEnvironmentVariable("MAX_HEAP_SIZE", "64M").addEnvironmentVariable("HEAP_NEWSIZE", "12m")

                .addConfigProperty("native_transport_port", port).addConfigProperty("disk_failure_policy", "stop_paranoid")

                .logger(new Slf4jLogger(LoggerFactory.getLogger("Cassandra")))

                .build();
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

        CqlSession session = this.session();

        CqlScript.ofClassPath("cassandra/keyspace.cql").forEachStatement(session::execute);
        CqlScript.ofClassPath("cassandra/test.cql").forEachStatement(session::execute);
        CqlScript.ofClassPath("cassandra/exec.cql").forEachStatement(session::execute);

    }

}
