package com.exemple.authorization.resource.core;

import org.springframework.util.Assert;

public final class ResourceExecutionContext {

    private static ThreadLocal<ResourceExecutionContext> executionContext = new ThreadLocal<>();

    private String keyspace;

    private ResourceExecutionContext() {

    }

    public static ResourceExecutionContext get() {

        if (executionContext.get() == null) {
            executionContext.set(new ResourceExecutionContext());
        }

        return executionContext.get();
    }

    public static void destroy() {

        executionContext.remove();
    }

    public String keyspace() {

        Assert.notNull(keyspace, "keyspace in ResourceExecutionContext must be required");

        return keyspace;
    }

    public void setKeyspace(String keyspace) {
        this.keyspace = keyspace;
    }
}
