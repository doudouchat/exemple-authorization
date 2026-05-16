package com.exemple.authorization.resource.core;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ResourceContext {

    public static final ScopedValue<String> KEYSPACE = ScopedValue.newInstance();

}
