package com.exemple.authorization.core;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Import;

import com.exemple.authorization.resource.core.ResourceConfiguration;
import com.exemple.service.application.core.ApplicationConfiguration;

@SpringBootApplication
@Import({ ApplicationConfiguration.class, ResourceConfiguration.class })
public class AuthorizationServerApplication extends SpringBootServletInitializer {

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(AuthorizationServerApplication.class);
    }

}
