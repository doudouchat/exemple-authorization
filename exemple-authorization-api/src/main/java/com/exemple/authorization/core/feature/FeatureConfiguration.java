package com.exemple.authorization.core.feature;

import java.util.logging.Level;

import org.glassfish.jersey.jackson.internal.jackson.jaxrs.json.JacksonJsonProvider;
import org.glassfish.jersey.logging.LoggingFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import com.exemple.authorization.core.feature.authorization.AuthorizationFeatureFilter;
import com.exemple.authorization.password.properties.PasswordProperties;

import jakarta.ws.rs.ApplicationPath;

@Configuration
@ApplicationPath("/ws")
@ComponentScan(basePackages = { "com.exemple.authorization.disconnection", "com.exemple.authorization.password", "com.exemple.authorization.login" })
@EnableConfigurationProperties(PasswordProperties.class)
public class FeatureConfiguration extends ResourceConfig {

    public static final String APP_HEADER = "app";

    public FeatureConfiguration() {

        // Resources
        packages(
                // login feature
                "com.exemple.authorization.login",
                // password feature
                "com.exemple.authorization.password",
                // disconnection feature
                "com.exemple.authorization.disconnection",
                // exception
                "com.exemple.authorization.core.feature.exception")
                // security
                .register(RolesAllowedDynamicFeature.class)
                .register(AuthorizationFeatureFilter.class)
                // logging
                .register(LoggingFeature.class)
                .property(LoggingFeature.LOGGING_FEATURE_VERBOSITY, LoggingFeature.Verbosity.PAYLOAD_ANY)
                .property(LoggingFeature.LOGGING_FEATURE_LOGGER_LEVEL, Level.FINE.getName())
                // JSON
                .register(JacksonJsonProvider.class);

    }
}
