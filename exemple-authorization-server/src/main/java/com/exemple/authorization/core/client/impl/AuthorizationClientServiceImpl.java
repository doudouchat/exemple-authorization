package com.exemple.authorization.core.client.impl;

import java.nio.charset.StandardCharsets;

import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.recipes.nodes.PersistentNode;
import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.KeeperException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Service;

import com.exemple.authorization.core.client.AuthorizationClientService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthorizationClientServiceImpl implements AuthorizationClientService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Qualifier("authorizationClientCuratorFramework")
    private final CuratorFramework client;

    @Override
    @SneakyThrows
    public ClientDetails get(String clientId) {

        try {

            return MAPPER.readValue(client.getData().forPath("/" + clientId), BaseClientDetails.class);

        } catch (KeeperException.NoNodeException e) {

            throw new BadCredentialsException("Client '" + clientId + "' not exists", e);
        }

    }

    @Override
    public void put(String clientId, ClientDetails clientDetails) {

        LOG.debug("Put Authorization client {} ", clientId);

        createAuthorization(clientId, MAPPER.convertValue(clientDetails, JsonNode.class));

    }

    private PersistentNode createAuthorization(String clientId, JsonNode data) {

        var node = new PersistentNode(client, CreateMode.PERSISTENT, false, "/" + clientId, data.toString().getBytes(StandardCharsets.UTF_8));
        node.start();

        return node;

    }

}
