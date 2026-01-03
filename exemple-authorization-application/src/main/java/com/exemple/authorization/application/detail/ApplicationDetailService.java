package com.exemple.authorization.application.detail;

import java.util.Optional;

import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.recipes.nodes.PersistentNode;
import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.KeeperException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.exemple.authorization.application.common.model.ApplicationDetail;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Service
@RequiredArgsConstructor
@Slf4j
public class ApplicationDetailService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Qualifier("applicationDetailCuratorFramework")
    private final CuratorFramework client;

    @SneakyThrows
    public Optional<ApplicationDetail> get(String application) {

        try {

            return Optional.of(MAPPER.readValue(client.getData().forPath("/" + application), ApplicationDetail.class));

        } catch (KeeperException.NoNodeException e) {

            LOG.warn("Application '" + application + "' not exists", e);

            return Optional.empty();
        }
    }

    public void put(String application, JsonNode detail) {

        LOG.debug("Put detail {} for application {}", detail, application);

        createDetail(application, detail);

    }

    private PersistentNode createDetail(String application, JsonNode detail) {

        var node = new PersistentNode(client, CreateMode.PERSISTENT, false, "/" + application, detail.toString().getBytes());
        node.start();

        return node;

    }

}
