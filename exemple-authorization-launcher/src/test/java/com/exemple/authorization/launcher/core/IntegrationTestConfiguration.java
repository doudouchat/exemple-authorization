package com.exemple.authorization.launcher.core;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.annotation.PostConstruct;

import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.security.crypto.bcrypt.BCrypt;

import com.datastax.oss.driver.api.core.CqlSession;
import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.exemple.authorization.application.core.ApplicationConfiguration;
import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.exemple.authorization.core.client.AuthorizationClientBuilder;
import com.exemple.authorization.core.client.AuthorizationClientConfiguration;
import com.exemple.authorization.resource.core.ResourceConfiguration;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.SneakyThrows;

@Configuration
@Import({ ResourceConfiguration.class, ApplicationConfiguration.class, AuthorizationClientConfiguration.class })
@ComponentScan(basePackages = "com.exemple.authorization.launcher", excludeFilters = @ComponentScan.Filter(SpringBootApplication.class))
public class IntegrationTestConfiguration {

    public static final String AUTHORIZATION_URL = System.getProperty("authorization.host", "http://localhost") + ":"
            + System.getProperty("authorization.port", "8084") + "/" + System.getProperty("authorization.contextpath", "ExempleAuthorization");

    public static final String APP_HEADER = "app";

    public static final String APP_USER = "test";

    public static final String APP_ADMIN = "admin";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private ApplicationDetailService applicationDetailService;

    @Autowired
    private AuthorizationClientBuilder authorizationClientBuilder;

    @Autowired
    private CqlSession session;

    private final Resource[] scripts;

    public IntegrationTestConfiguration(@Value("${cassandra.scripts:}") String... scripts) {
        this.scripts = Arrays.stream(scripts).map(File::new).map(FileSystemResource::new).toArray(Resource[]::new);

    }

    @Bean
    public static PropertySourcesPlaceholderConfigurer propertyPlaceholderConfigurer() {

        PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer = new PropertySourcesPlaceholderConfigurer();

        YamlPropertiesFactoryBean properties = new YamlPropertiesFactoryBean();
        properties.setResources(new ClassPathResource("exemple-authorization-test.yml"));

        propertySourcesPlaceholderConfigurer.setProperties(properties.getObject());
        return propertySourcesPlaceholderConfigurer;
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

        // ADMIN

        ApplicationDetail adminDetail = ApplicationDetail.builder()
                .keyspace("test")
                .clientId("admin")
                .build();

        applicationDetailService.put("admin", MAPPER.convertValue(adminDetail, JsonNode.class));

    }

    @PostConstruct
    public void initAuthorization() throws Exception {

        String password = "{bcrypt}" + BCrypt.hashpw("secret", BCrypt.gensalt());

        authorizationClientBuilder

                .withClient("test").secret(password).authorizedGrantTypes("client_credentials").redirectUris("xxx")
                .scopes("account", "login:update", "login:head").autoApprove("account", "login:update", "login:head").authorities("ROLE_APP")
                .resourceIds("exemple").additionalInformation("keyspace=test")

                .and()

                .withClient("test_user").secret(password).authorizedGrantTypes("password", "authorization_code", "implicit", "refresh_token")
                .redirectUris("xxx")
                .scopes("account", "login:head", "login:update", "login:read", "login:delete")
                .autoApprove("account", "login:head", "login:update", "login:read", "login:delete").authorities("ROLE_APP").resourceIds("exemple")
                .additionalInformation("keyspace=test")

                .and()

                .withClient("back_user").secret(password).authorizedGrantTypes("password").scopes("back").autoApprove("back").authorities("ROLE_BACK")
                .resourceIds("exemple").additionalInformation("keyspace=test")

                .and()

                .withClient("admin").secret(password).authorizedGrantTypes("client_credentials").scopes("xxx").autoApprove("xxx")
                .authorities("ROLE_TRUSTED_CLIENT").resourceIds("exemple").additionalInformation("keyspace=test")

                .and()

                .withClient("resource").secret(password).authorizedGrantTypes("client_credentials").authorities("ROLE_TRUSTED_CLIENT")

                .and().build();
    }

    @SneakyThrows
    private static String[] splitScript(Resource script) {
        return FileUtils.readFileToString(script.getFile(), StandardCharsets.UTF_8).trim().split(";");
    }

}
