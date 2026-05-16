package com.exemple.authorization.core.feature.context;

import java.lang.reflect.Proxy;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.glassfish.jersey.server.ContainerRequest;
import org.springframework.stereotype.Component;

import com.exemple.authorization.application.common.exception.NotFoundApplicationException;
import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.exemple.authorization.core.feature.FeatureConfiguration;
import com.exemple.authorization.resource.core.ResourceContext;

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Request;
import lombok.SneakyThrows;

@Aspect
@Component
@Priority(Priorities.USER)
public class CreateServiceContext implements ContainerRequestFilter {

    @Context
    private Request request;

    private final ApplicationDetailService applicationDetailService;

    @Inject
    public CreateServiceContext(ApplicationDetailService applicationDetailService) {
        this.applicationDetailService = applicationDetailService;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {

        // NOP
    }

    @Around("@annotation(jakarta.ws.rs.GET) || "
            + "@annotation(jakarta.ws.rs.HEAD) || "
            + "@annotation(jakarta.ws.rs.POST) || "
            + "@annotation(jakarta.ws.rs.PUT) || "
            + "@annotation(jakarta.ws.rs.PATCH)")
    public Object execute(ProceedingJoinPoint joinPoint) throws Throwable {

        String applicationName = getHeader(FeatureConfiguration.APP_HEADER);
        var applicationDetail = applicationDetailService.get(applicationName)
                .orElseThrow(() -> new NotFoundApplicationException(applicationName));

        return ScopedValue
                .where(ResourceContext.KEYSPACE, applicationDetail.getKeyspace()).call(() -> proceed(joinPoint));

    }

    @SneakyThrows
    private static Object proceed(ProceedingJoinPoint joinPoint) {
        return joinPoint.proceed();
    }

    private <T> T getHeader(String name) throws Throwable {

        return (T) Proxy.getInvocationHandler(request).invoke(request, ContainerRequest.class.getMethod("getHeaderString", String.class),
                new Object[] { name });
    }

}
