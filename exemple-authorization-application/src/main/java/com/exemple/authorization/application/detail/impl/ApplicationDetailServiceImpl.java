package com.exemple.authorization.application.detail.impl;

import java.nio.charset.StandardCharsets;

import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.recipes.nodes.PersistentNode;
import org.apache.zookeeper.CreateMode;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.exemple.authorization.application.common.exception.NotFoundApplicationException;
import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class ApplicationDetailServiceImpl implements ApplicationDetailService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    @Qualifier("applicationDetailCuratorFramework")
    private final CuratorFramework client;

    @Override
    public ApplicationDetail get(String application) {

        try {

            return MAPPER.readValue(client.getData().forPath("/" + application), ApplicationDetail.class);

        } catch (Exception e) {

            throw new NotFoundApplicationException(application, e);
        }

    }

    @Override
    public void put(String application, JsonNode detail) {

        LOG.debug("Put detail {} for application {}", detail, application);

        createDetail(application, detail);

    }

    private PersistentNode createDetail(String application, JsonNode detail) {

        var node = new PersistentNode(client, CreateMode.PERSISTENT, false, "/" + application, detail.toString().getBytes(StandardCharsets.UTF_8));
        node.start();

        return node;

    }

}
