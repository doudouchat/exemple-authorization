package com.exemple.authorization.application.common.model;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.Getter;
import lombok.Singular;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonPOJOBuilder;

@Builder
@Getter
//TODO move to @Jacksonized
@JsonDeserialize(builder = ApplicationDetail.ApplicationDetailBuilder.class)
public class ApplicationDetail {

    @JsonProperty("authorization_keyspace")
    private final String keyspace;

    @JsonProperty("authorization_clientIds")
    @Singular
    private final Set<String> clientIds;

    private final Long expiryTimePassword;

    @JsonPOJOBuilder(withPrefix = "")
    public static class ApplicationDetailBuilder {
    }

}
