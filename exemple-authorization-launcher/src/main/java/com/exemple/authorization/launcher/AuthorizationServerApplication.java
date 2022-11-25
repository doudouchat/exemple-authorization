package com.exemple.authorization.launcher;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.cassandra.CassandraAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.PropertySource;

import com.exemple.authorization.application.core.ApplicationConfiguration;
import com.exemple.authorization.core.AuthorizationConfiguration;
import com.exemple.authorization.core.authentication.AuthenticationConfiguration;
import com.exemple.authorization.core.client.AuthorizationClientConfiguration;
import com.exemple.authorization.core.feature.FeatureConfiguration;
import com.exemple.authorization.core.rsa.KeystoreConfiguration;
import com.exemple.authorization.core.session.HazelcastHttpSessionConfiguration;
import com.exemple.authorization.core.swagger.SwaggerConfiguration;
import com.exemple.authorization.core.token.AuthorizationTokenConfiguration;
import com.exemple.authorization.resource.core.ResourceConfiguration;

@SpringBootApplication(exclude = CassandraAutoConfiguration.class)
@Import({ AuthorizationConfiguration.class,
        AuthenticationConfiguration.class,
        AuthorizationTokenConfiguration.class,
        HazelcastHttpSessionConfiguration.class,
        SwaggerConfiguration.class,
        AuthorizationClientConfiguration.class,
        FeatureConfiguration.class,
        ApplicationConfiguration.class,
        ResourceConfiguration.class,
        KeystoreConfiguration.class })
@PropertySource("classpath:default.properties")
public class AuthorizationServerApplication extends SpringBootServletInitializer {

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(AuthorizationServerApplication.class);
    }

}
