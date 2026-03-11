package com.exemple.authorization.core.client.resource;

import java.util.Optional;

import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.recipes.nodes.PersistentNode;
import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.KeeperException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import com.exemple.authorization.core.client.AuthorizationClient;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthorizationClientResource {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Qualifier("authorizationClientCuratorFramework")
    private final CuratorFramework client;

    @SneakyThrows
    public Optional<AuthorizationClient> get(String clientId) {

        try {

            return Optional.of(MAPPER.readValue(client.getData().forPath("/" + clientId), AuthorizationClient.class));

        } catch (KeeperException.NoNodeException e) {

            LOG.debug("Client '" + clientId + "' not exists", e);
            return Optional.empty();
        }

    }

    public void save(AuthorizationClient client) {

        LOG.debug("Put Authorization client {} {}", client.getClientId(), client.getId());

        createAuthorization(client.getClientId(), MAPPER.convertValue(client, JsonNode.class));
        createAuthorization(client.getId(), MAPPER.convertValue(client, JsonNode.class));

    }

    private PersistentNode createAuthorization(String clientId, JsonNode data) {

        var node = new PersistentNode(client, CreateMode.PERSISTENT, false, "/" + clientId, data.toString().getBytes());
        node.start();

        return node;

    }

}
