package com.exemple.authorization.application.detail;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.exemple.authorization.application.core.ApplicationTestConfiguration;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest(classes = ApplicationTestConfiguration.class)
@ActiveProfiles("test")
class ApplicationDetailServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private ApplicationDetailService service;

    @Test
    @DisplayName("create application in zookeeper")
    void createApplication() {

        // setup application
        Map<String, Object> application = Map.of(
                "authorization_keyspace", "keyspace1",
                "expiryTimePassword", 100L,
                "authorization_clientIds", Set.of("clientId1"),
                "other", "other");

        // when save application
        service.put("app", MAPPER.convertValue(application, JsonNode.class));

        // Then retrieve application
        Optional<ApplicationDetail> applicationDetail = service.get("app");

        // And check details
        assertThat(applicationDetail).hasValueSatisfying(detail -> assertAll(
                () -> assertThat(detail.getKeyspace()).isEqualTo("keyspace1"),
                () -> assertThat(detail.getExpiryTimePassword()).isEqualTo(100L),
                () -> assertThat(detail.getClientIds()).containsOnly("clientId1")));

    }

    @Test
    @DisplayName("check exception if application is not found")
    void getFailureNotFoundApplication() {

        // setup random application
        String application = UUID.randomUUID().toString();

        // When perform get
        Optional<ApplicationDetail> applicationDetail = service.get(application);

        // Then check application is missing
        assertThat(applicationDetail).as("application % is unexpected", application).isEmpty();

    }

    @Test
    @DisplayName("check exception if application is incorrect")
    void getFailureBecauseApplicationIsIncorrect() {

        // setup save application
        service.put("fails", MAPPER.createArrayNode());

        // When perform get
        Throwable throwable = catchThrowable(() -> service.get("fails"));

        // Then check throwable
        assertThat(throwable).isInstanceOf(IOException.class);
    }

}
