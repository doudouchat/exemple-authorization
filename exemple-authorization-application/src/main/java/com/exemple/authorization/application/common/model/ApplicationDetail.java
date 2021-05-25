package com.exemple.authorization.application.common.model;

import java.util.Collections;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ApplicationDetail {

    @JsonProperty("authorization_keyspace")
    private String keyspace;

    @JsonProperty("authorization_clientIds")
    private Set<String> clientIds;

    private Long expiryTimePassword;

    public String getKeyspace() {
        return keyspace;
    }

    public void setKeyspace(String keyspace) {
        this.keyspace = keyspace;
    }

    public Long getExpiryTimePassword() {
        return expiryTimePassword;
    }

    public void setExpiryTimePassword(Long expiryTimePassword) {
        this.expiryTimePassword = expiryTimePassword;
    }

    public Set<String> getClientIds() {
        return Collections.unmodifiableSet(clientIds);
    }

    public void setClientIds(Set<String> clientIds) {
        this.clientIds = Collections.unmodifiableSet(clientIds);
    }

}
