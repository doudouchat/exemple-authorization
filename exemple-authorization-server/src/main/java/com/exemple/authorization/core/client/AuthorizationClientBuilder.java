package com.exemple.authorization.core.client;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.config.annotation.builders.ClientDetailsServiceBuilder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.stereotype.Component;

@Component
public class AuthorizationClientBuilder extends ClientDetailsServiceBuilder<AuthorizationClientBuilder> {

    private final AuthorizationClientService service;

    private final Map<String, ClientDetails> clientDetails;

    public AuthorizationClientBuilder(AuthorizationClientService service) {

        this.service = service;
        this.clientDetails = new HashMap<>();

    }

    @Override
    protected void addClient(String clientId, ClientDetails value) {
        clientDetails.put(clientId, value);
    }

    @Override
    protected ClientDetailsService performBuild() {

        this.clientDetails.forEach(service::put);

        return service::get;
    }

}
