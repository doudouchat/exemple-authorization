package com.exemple.authorization.launcher.core;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.apache.commons.io.FileUtils;
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
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import com.datastax.oss.driver.api.core.CqlSession;
import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.exemple.authorization.application.core.ApplicationConfiguration;
import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.exemple.authorization.core.client.AuthorizationClient;
import com.exemple.authorization.core.client.resource.AuthorizationClientResource;
import com.exemple.authorization.core.client.resource.AuthorizationClientResourceConfiguration;
import com.exemple.authorization.resource.core.ResourceConfiguration;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.annotation.PostConstruct;
import lombok.SneakyThrows;

@Configuration
@Import({ ResourceConfiguration.class, ApplicationConfiguration.class, AuthorizationClientResourceConfiguration.class })
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
    private AuthorizationClientResource authorizationClientResource;

    @Autowired
    private CqlSession session;

    @Autowired
    private KafkaConsumer<?, ?> consumerNewPassword;

    private final Resource[] scripts;

    public IntegrationTestConfiguration(@Value("${cassandra.scripts:}") String... scripts) {
        this.scripts = Arrays.stream(scripts).map(File::new).map(FileSystemResource::new).toArray(Resource[]::new);

    }

    @PostConstruct
    public void suscribeConsumerNewPassword() throws Exception {

        consumerNewPassword.subscribe(List.of("new_password"), new ConsumerRebalanceListener() {

            @Override
            public void onPartitionsRevoked(Collection<TopicPartition> partitions) {
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

    @PostConstruct
    public void initAuthorization() throws Exception {

        var secret = "{bcrypt}" + BCrypt.hashpw("secret", BCrypt.gensalt());

        var testClient = AuthorizationClient.builder()
                .id(UUID.randomUUID().toString())
                .clientId("test")
                .clientSecret(secret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue())
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                .redirectUri("http://xxx")
                .scope("account")
                .scope("login:update")
                .scope("login:head")
                .scope("ROLE_APP")
                .requireAuthorizationConsent(false)
                .build();

        authorizationClientResource.save(testClient);

        var resourceClient = AuthorizationClient.builder()
                .id(UUID.randomUUID().toString())
                .clientId("resource")
                .clientSecret(secret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue())
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER.getValue())
                .requireAuthorizationConsent(false)
                .build();

        authorizationClientResource.save(resourceClient);

        var testUserClient = AuthorizationClient.builder()
                .id(UUID.randomUUID().toString())
                .clientId("test_user")
                .clientSecret(secret)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD.getValue())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN.getValue())
                .redirectUri("http://xxx")
                .scope("account")
                .scope("login:update")
                .scope("login:head")
                .scope("login:read")
                .scope("login:delete")
                .requireAuthorizationConsent(false)
                .build();

        authorizationClientResource.save(testUserClient);

        var testBackClient = AuthorizationClient.builder()
                .id(UUID.randomUUID().toString())
                .clientId("test_back")
                .clientSecret(secret)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD.getValue())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN.getValue())
                .redirectUri("http://xxx")
                .scope("ROLE_BACK")
                .requireAuthorizationConsent(false)
                .build();

        authorizationClientResource.save(testBackClient);

    }

    @SneakyThrows
    private static String[] splitScript(Resource script) {
        return FileUtils.readFileToString(script.getFile(), StandardCharsets.UTF_8).trim().split(";");
    }

}
