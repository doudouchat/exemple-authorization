package com.exemple.authorization.application.detail;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import com.exemple.authorization.application.common.exception.NotFoundApplicationException;
import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.exemple.authorization.application.core.ApplicationTestConfiguration;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringJUnitConfig(ApplicationTestConfiguration.class)
class ApplicationDetailServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private ApplicationDetailService service;

    @Test
    @DisplayName("create application in zookeeper")
    void createApplication() {

        // setup application
        Map<String, Object> detail = Map.of(
                "authorization_keyspace", "keyspace1",
                "expiryTimePassword", 100L,
                "authorization_clientIds", Set.of("clientId1"),
                "other", "other");

        // when save application
        service.put("app", MAPPER.convertValue(detail, JsonNode.class));

        // Then retrieve application
        ApplicationDetail applicationDetail = service.get("app");

        // And check details
        assertAll(
                () -> assertThat(applicationDetail.getKeyspace()).isEqualTo("keyspace1"),
                () -> assertThat(applicationDetail.getExpiryTimePassword()).isEqualTo(100L),
                () -> assertThat(applicationDetail.getClientIds()).containsOnly("clientId1"));

    }

    @Test
    void getFailureNotFoundApplication() {

        // setup random application
        String application = UUID.randomUUID().toString();

        // When perform get
        Throwable throwable = catchThrowable(() -> service.get(application));

        // Then check throwable
        assertThat(throwable).isInstanceOfSatisfying(NotFoundApplicationException.class,
                exception -> assertAll(
                        () -> assertThat(exception.getApplication()).isEqualTo(application)));

    }

}
