package com.exemple.authorization.resource.oauth2.model;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;

import com.datastax.oss.driver.api.mapper.annotations.CqlName;
import com.datastax.oss.driver.api.mapper.annotations.Entity;
import com.datastax.oss.driver.api.mapper.annotations.PartitionKey;

import lombok.Getter;
import lombok.Setter;
import tools.jackson.databind.JsonNode;

@Entity
@CqlName("oauth2")
@Getter
@Setter
public class OAuth2Entity {

    @PartitionKey
    private String id;

    private String principalName;

    private Set<String> authorizedScopes = Collections.emptySet();

    private String authorizationGrantType;

    private String registeredClientId;

    private JsonNode attributes;

    private String accessTokenValue;

    private Instant accessTokenIssuedAt;

    private Instant accessTokenExpiresAt;

    private JsonNode accessTokenMetadata;

    private String accessTokenType;

    private Set<String> accessTokenScopes;

    private String authorizationCodeValue;

    private Instant authorizationCodeIssuedAt;

    private Instant authorizationCodeExpiresAt;

    private JsonNode authorizationCodeMetadata;

    private String refreshTokenValue;

    private Instant refreshTokenIssuedAt;

    private Instant refreshTokenExpiresAt;

    private JsonNode refreshTokenMetadata;

}
