package com.exemple.authorization.core.resource.keyspace;

import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.stereotype.Component;

import com.exemple.authorization.core.client.AuthorizationClientService;
import com.exemple.authorization.resource.core.ResourceExecutionContext;

@Component
public class AuthorizationResourceKeyspace {

    private final AuthorizationClientService authorizationClientService;

    public AuthorizationResourceKeyspace(AuthorizationClientService authorizationClientService) {
        this.authorizationClientService = authorizationClientService;
    }

    public void initKeyspace(String keyspace) {

        ResourceExecutionContext.get().setKeyspace(keyspace);
    }

    public void initKeyspace(OAuth2Request oAuth2Request) {

        initKeyspace(authorizationClientService.get(oAuth2Request.getClientId()));

    }

    public void initKeyspace(ClientDetails client) {

        initKeyspace((String) client.getAdditionalInformation().get("keyspace"));

    }

}
