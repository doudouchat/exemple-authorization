package com.exemple.authorization.integration.core;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.crypto.bcrypt.BCrypt;

import com.exemple.authorization.core.client.AuthorizationClientBuilder;
import com.exemple.authorization.core.client.AuthorizationClientConfiguration;
import com.exemple.authorization.resource.core.ResourceConfiguration;
import com.exemple.service.application.common.model.ApplicationDetail;
import com.exemple.service.application.core.ApplicationConfiguration;
import com.exemple.service.application.detail.ApplicationDetailService;
import com.google.common.collect.Sets;

@Configuration
@Import({ ResourceConfiguration.class, ApplicationConfiguration.class, AuthorizationClientConfiguration.class })
public class IntegrationTestConfiguration {

    public static final String AUTHORIZATION_URL = System.getProperty("authorization.host", "http://localhost") + ":"
            + System.getProperty("authorization.port", "8084") + "/" + System.getProperty("authorization.contextpath", "ExempleAuthorization");

    public static final String APP_HEADER = "app";

    public static final String APP_USER = "test";

    public static final String APP_ADMIN = "admin";

    @Autowired
    private ApplicationDetailService applicationDetailService;

    @Autowired
    private AuthorizationClientBuilder authorizationClientBuilder;

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

        // APP

        ApplicationDetail detail = new ApplicationDetail();
        detail.setKeyspace("test");
        detail.setClientIds(Sets.newHashSet("test", "test_user"));

        applicationDetailService.put("test", detail);

        // ADMIN

        ApplicationDetail adminDetail = new ApplicationDetail();
        adminDetail.setKeyspace("test");
        adminDetail.setClientIds(Sets.newHashSet("admin"));

        applicationDetailService.put("admin", adminDetail);

    }

    @PostConstruct
    public void initAuthorization() throws Exception {

        String password = "{bcrypt}" + BCrypt.hashpw("secret", BCrypt.gensalt());

        authorizationClientBuilder

                .withClient("test_user").secret(password).authorizedGrantTypes("password", "authorization_code", "refresh_token").redirectUris("xxx")
                .scopes("account").autoApprove("account").authorities("ROLE_APP").resourceIds("exemple").additionalInformation("keyspace=test")

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

}
