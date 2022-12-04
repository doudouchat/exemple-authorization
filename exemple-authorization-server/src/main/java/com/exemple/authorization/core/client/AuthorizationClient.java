package com.exemple.authorization.core.client;

import java.util.List;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import lombok.Builder;
import lombok.Getter;
import lombok.Singular;
import lombok.extern.jackson.Jacksonized;

@Builder
@Getter
@Jacksonized
public class AuthorizationClient {

    private final String id;

    private final String clientId;

    private final String clientSecret;

    @Singular
    private final List<String> clientAuthenticationMethods;

    @Singular
    private final List<String> authorizationGrantTypes;

    @Singular(value = "redirectUri")
    private final List<String> redirectUris;

    @Singular
    private final List<String> scopes;

    private final boolean requireAuthorizationConsent;

    public RegisteredClient buildRegisteredClient() {

        var registeredClient = RegisteredClient.withId(this.id)
                .clientId(this.clientId)
                .clientSecret(this.clientSecret)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(this.isRequireAuthorizationConsent())
                        .build());

        this.redirectUris.forEach(registeredClient::redirectUri);

        this.authorizationGrantTypes.stream()
                .map(AuthorizationGrantType::new)
                .forEach(registeredClient::authorizationGrantType);

        this.clientAuthenticationMethods.stream()
                .map(ClientAuthenticationMethod::new)
                .forEach(registeredClient::clientAuthenticationMethod);

        this.scopes.stream().forEach(registeredClient::scope);

        return registeredClient.build();
    }

}
