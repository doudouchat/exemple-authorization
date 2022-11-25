package com.exemple.authorization.core.feature;

import javax.annotation.security.RolesAllowed;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import io.swagger.v3.oas.annotations.Hidden;

@Configuration
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
        @Produces(javax.ws.rs.core.MediaType.APPLICATION_JSON)
        @RolesAllowed("test:read")
        public javax.ws.rs.core.Response get() {

            return javax.ws.rs.core.Response.ok().build();

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
