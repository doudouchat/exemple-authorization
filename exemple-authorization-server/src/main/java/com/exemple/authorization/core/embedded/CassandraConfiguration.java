package com.exemple.authorization.core.embedded;

import java.io.File;
import java.io.FileNotFoundException;
import java.time.Duration;
import java.util.Arrays;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ResourceUtils;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.config.DriverConfigLoader;
import com.github.nosan.embedded.cassandra.Cassandra;
import com.github.nosan.embedded.cassandra.CassandraBuilder;
import com.github.nosan.embedded.cassandra.commons.FileSystemResource;
import com.github.nosan.embedded.cassandra.commons.Resource;
import com.github.nosan.embedded.cassandra.commons.logging.Slf4jLogger;
import com.github.nosan.embedded.cassandra.cql.CqlScript;
import com.github.nosan.embedded.cassandra.cql.ResourceCqlScript;

@Configuration
@ConditionalOnProperty(value = { "port", "version" }, prefix = "authorization.embedded.cassandra")
public class CassandraConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(CassandraConfiguration.class);

    private final File cassandraResource;

    private final int port;

    private final String version;

    private final Resource[] scripts;

    private final int startupTimeout;

    public CassandraConfiguration(@Value("${authorization.resource.cassandra.resource_configuration}") String cassandraResource,
            @Value("${authorization.embedded.cassandra.port}") int port, @Value("${authorization.embedded.cassandra.version}") String version,
            @Value("${authorization.embedded.cassandra.startup_timeout:120}") int startupTimeout,
            @Value("${authorization.embedded.cassandra.scripts}") String... scripts) throws FileNotFoundException {
        this.cassandraResource = ResourceUtils.getFile(cassandraResource);
        this.port = port;
        this.version = version;
        this.startupTimeout = startupTimeout;
        this.scripts = Arrays.stream(scripts).map(File::new).map(FileSystemResource::new).toArray(Resource[]::new);
    }

    @Bean
    public Cassandra embeddedCassandra() {

        return new CassandraBuilder()

                .version(version)

                .addEnvironmentVariable("MAX_HEAP_SIZE", "64M").addEnvironmentVariable("HEAP_NEWSIZE", "12M")

                .addConfigProperty("native_transport_port", port).addConfigProperty("disk_failure_policy", "stop_paranoid")

                .logger(new Slf4jLogger(LoggerFactory.getLogger("Cassandra")))

                .startupTimeout(Duration.ofSeconds(startupTimeout))

                .build();
    }

    @PostConstruct
    public void initKeyspace() {

        LOG.info("STARTING EMBEDDED CASSANDRA");
        embeddedCassandra().start();

        DriverConfigLoader loader = DriverConfigLoader.fromFile(cassandraResource);

        try (CqlSession session = CqlSession.builder().withConfigLoader(loader).build()) {
            Arrays.stream(scripts).map(ResourceCqlScript::new).forEach((CqlScript script) -> script.forEachStatement(session::execute));
        }

    }

    @PreDestroy
    public void shutdownCassandra() {

        LOG.info("SHUTDOWN EMBEDDED CASSANDRA");
        embeddedCassandra().stop();

    }

}
