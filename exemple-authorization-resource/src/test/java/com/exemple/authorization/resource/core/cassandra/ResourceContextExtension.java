package com.exemple.authorization.resource.core.cassandra;

import java.lang.reflect.Method;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.InvocationInterceptor;
import org.junit.jupiter.api.extension.ReflectiveInvocationContext;

import com.exemple.authorization.resource.core.ResourceContext;

import lombok.SneakyThrows;

public class ResourceContextExtension implements InvocationInterceptor {

    @Override
    public void interceptBeforeEachMethod(Invocation<@Nullable Void> invocation,
            ReflectiveInvocationContext<Method> invocationContext, ExtensionContext extensionContext) throws Throwable {

        this.interceptTestMethod(invocation, invocationContext, extensionContext);
    }

    @Override
    public void interceptTestMethod(Invocation<@Nullable Void> invocation,
            ReflectiveInvocationContext<Method> invocationContext, ExtensionContext extensionContext) throws Throwable {

        extensionContext.getTestMethod()
                .map(method -> method.getAnnotation(WithResourceContext.class))
                .map(WithResourceContext::keyspace)
                .ifPresentOrElse(keyspace -> {
                    ScopedValue.where(ResourceContext.KEYSPACE, keyspace).run(() -> proceed(invocation));
                }, () -> proceed(invocation));
    }

    @SneakyThrows
    private static void proceed(Invocation<@Nullable Void> invocation) {
        invocation.proceed();
    }

}
