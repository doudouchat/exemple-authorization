package com.exemple.authorization.core.feature;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;

import com.exemple.authorization.AuthorizationJwtConfiguration;

import io.swagger.v3.oas.annotations.Hidden;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.SecurityContext;

@Configuration
@Import(AuthorizationJwtConfiguration.class)
@Primary
public class FeatureTestConfiguration extends FeatureConfiguration {

    @Bean
    public TestApi testApi() {

        TestApi api = new TestApi();
        this.register(api);

        return api;

    }

    @Bean
    public TestFilter testFilter() {

        TestFilter filter = new TestFilter();
        this.register(filter);

        return filter;

    }

    @Path("/v1/test")
    @Hidden
    public static class TestApi {

        @GET
        @Produces(jakarta.ws.rs.core.MediaType.APPLICATION_JSON)
        @RolesAllowed("test:read")
        public jakarta.ws.rs.core.Response get() {

            return jakarta.ws.rs.core.Response.ok().build();

        }

    }

    public static class TestFilter implements ContainerRequestFilter {

        public SecurityContext context;

        @Override
        public void filter(ContainerRequestContext requestContext) {

            context = requestContext.getSecurityContext();

        }

    }

}
