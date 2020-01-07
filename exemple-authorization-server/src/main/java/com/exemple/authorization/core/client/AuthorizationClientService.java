package com.exemple.authorization.core.client;

import org.springframework.security.oauth2.provider.ClientDetails;

public interface AuthorizationClientService {

    ClientDetails get(String clientId);

    void put(String clientId, ClientDetails clientDetails);

}
