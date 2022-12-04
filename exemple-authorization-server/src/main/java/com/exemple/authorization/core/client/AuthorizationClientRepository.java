package com.exemple.authorization.core.client;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import com.exemple.authorization.core.client.resource.AuthorizationClientResource;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AuthorizationClientRepository implements RegisteredClientRepository {

    private final AuthorizationClientResource authorizationClientResource;

    @Override
    public void save(RegisteredClient registeredClient) {
        // NOP
    }

    @Override
    public RegisteredClient findById(String id) {
        return authorizationClientResource.get(id).map(AuthorizationClient::buildRegisteredClient).orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return authorizationClientResource.get(clientId).map(AuthorizationClient::buildRegisteredClient).orElse(null);
    }
}
