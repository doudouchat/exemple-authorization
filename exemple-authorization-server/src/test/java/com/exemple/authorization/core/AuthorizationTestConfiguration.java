package com.exemple.authorization.core;

import org.mockito.Mockito;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.cassandra.CassandraAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.ClassPathResource;

import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.exemple.authorization.core.authentication.AuthenticationConfiguration;
import com.exemple.authorization.core.client.AuthorizationClientTestConfiguration;
import com.exemple.authorization.core.feature.FeatureTestConfiguration;
import com.exemple.authorization.core.resource.keyspace.AuthorizationResourceKeyspace;
import com.exemple.authorization.core.session.HazelcastHttpSessionConfiguration;
import com.exemple.authorization.core.swagger.SwaggerConfiguration;
import com.exemple.authorization.core.token.AuthorizationTokenConfiguration;
import com.exemple.authorization.resource.login.LoginResource;

@Configuration
@Import({ AuthorizationConfiguration.class, AuthenticationConfiguration.class, AuthorizationTokenConfiguration.class,
        HazelcastHttpSessionConfiguration.class, SwaggerConfiguration.class, AuthorizationClientTestConfiguration.class,
        FeatureTestConfiguration.class })
@ComponentScan(basePackageClasses = AuthorizationResourceKeyspace.class)
@EnableAutoConfiguration(exclude = CassandraAutoConfiguration.class)
public class AuthorizationTestConfiguration {

    @Bean
    public LoginResource loginResource() {
        return Mockito.mock(LoginResource.class);
    }

    @Bean
    public ApplicationDetailService ApplicationDetailService() {

        ApplicationDetailService service = Mockito.mock(ApplicationDetailService.class);

        ApplicationDetail detail = ApplicationDetail.builder()
                .keyspace("test")
                .clientId("clientId1")
                .build();

        Mockito.when(service.get(Mockito.anyString())).thenReturn(detail);

        return service;
    }

    @Bean
    public static PropertySourcesPlaceholderConfigurer propertyPlaceholderConfigurer() {

        PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer = new PropertySourcesPlaceholderConfigurer();

        YamlPropertiesFactoryBean properties = new YamlPropertiesFactoryBean();
        properties.setResources(new ClassPathResource("exemple-authorization-test.yml"));

        propertySourcesPlaceholderConfigurer.setProperties(properties.getObject());
        return propertySourcesPlaceholderConfigurer;
    }
}
