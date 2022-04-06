package com.exemple.authorization.application.common.model;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.Getter;
import lombok.Singular;
import lombok.extern.jackson.Jacksonized;

@Builder
@Getter
@Jacksonized
public class ApplicationDetail {

    @JsonProperty("authorization_keyspace")
    private final String keyspace;

    @JsonProperty("authorization_clientIds")
    @Singular
    private final Set<String> clientIds;

    private final Long expiryTimePassword;

}
