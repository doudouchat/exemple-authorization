package com.exemple.authorization.application.detail.impl;

import java.nio.charset.StandardCharsets;

import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.recipes.nodes.PersistentNode;
import org.apache.zookeeper.CreateMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.exemple.authorization.application.common.exception.NotFoundApplicationException;
import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class ApplicationDetailServiceImpl implements ApplicationDetailService {

    private static final Logger LOG = LoggerFactory.getLogger(ApplicationDetailServiceImpl.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    private final CuratorFramework client;

    public ApplicationDetailServiceImpl(@Qualifier("applicationDetailCuratorFramework") CuratorFramework client) {
        this.client = client;

    }

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

        PersistentNode node = new PersistentNode(client, CreateMode.PERSISTENT, false, "/" + application,
                detail.toString().getBytes(StandardCharsets.UTF_8));
        node.start();

        return node;

    }

}
