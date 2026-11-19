package com.exemple.authorization.launcher.core;

import java.io.File;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.kafka.clients.consumer.ConsumerRebalanceListener;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.TopicPartition;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import com.datastax.oss.driver.api.core.CqlSession;
import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.exemple.authorization.application.core.ApplicationConfiguration;
import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.exemple.authorization.resource.core.ResourceConfiguration;

import jakarta.annotation.PostConstruct;
import lombok.SneakyThrows;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Configuration
@Import({ ResourceConfiguration.class, ApplicationConfiguration.class })
@ComponentScan(basePackages = "com.exemple.authorization.launcher", excludeFilters = @ComponentScan.Filter(SpringBootApplication.class))
public class IntegrationTestConfiguration {

    public static final String AUTHORIZATION_URL = System.getProperty("authorization.host", "http://localhost") + ":"
            + System.getProperty("authorization.port", "8084") + "/" + System.getProperty("authorization.contextpath", "ExempleAuthorization");

    public static final String APP_HEADER = "app";

    public static final String APP_USER = "test";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private ApplicationDetailService applicationDetailService;

    @Autowired
    private CqlSession session;

    @Autowired
    private KafkaConsumer<?, ?> consumerNewPassword;

    private final Resource[] scripts;

    public IntegrationTestConfiguration(@Value("${cassandra.scripts:}") String... scripts) {
        this.scripts = Arrays.stream(scripts).map(File::new).map(FileSystemResource::new).toArray(Resource[]::new);

    }

    @PostConstruct
    public void suscribeConsumerNewPassword() {

        consumerNewPassword.subscribe(List.of("new_password"), new ConsumerRebalanceListener() {

            @Override
            public void onPartitionsRevoked(Collection<TopicPartition> partitions) {
                // NOP
            }

            @Override
            public void onPartitionsAssigned(Collection<TopicPartition> partitions) {
                consumerNewPassword.seekToBeginning(partitions);
            }
        });
    }

    @PostConstruct
    public void initSchema() {

        // INIT KEYSPACE

        Arrays.stream(scripts).flatMap((Resource script) -> Arrays.stream(splitScript(script))).forEach(session::execute);

        // APP

        ApplicationDetail detail = ApplicationDetail.builder()
                .keyspace("test")
                .clientId("test")
                .clientId("test_user")
                .build();

        applicationDetailService.put("test", MAPPER.convertValue(detail, JsonNode.class));

    }

    @SneakyThrows
    private static String[] splitScript(Resource script) {
        return script.getContentAsString(Charset.defaultCharset()).trim().split(";");
    }

}
