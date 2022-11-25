package com.exemple.authorization.core.keyspace;

import org.springframework.stereotype.Component;

import com.exemple.authorization.resource.core.ResourceExecutionContext;

@Component
public class ApiResourceKeyspace {

    public void initKeyspace(String keyspace) {

        ResourceExecutionContext.get().setKeyspace(keyspace);
    }
}
