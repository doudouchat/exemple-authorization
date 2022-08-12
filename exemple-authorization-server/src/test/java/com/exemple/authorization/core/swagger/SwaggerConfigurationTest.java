package com.exemple.authorization.core.swagger;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.List;

import javax.ws.rs.core.Response.Status;

import org.apache.curator.shaded.com.google.common.collect.ImmutableList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.util.ResourceUtils;

import com.exemple.authorization.common.LoggingFilter;
import com.exemple.authorization.core.AuthorizationTestConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(classes = { AuthorizationTestConfiguration.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
@Slf4j
class SwaggerConfigurationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private TestRestTemplate restTemplate;

    private RequestSpecification requestSpecification;

    @BeforeEach
    private void before() {

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG));

    }

    @Test
    void swagger() throws IOException {

        // When perform swagger
        Response response = requestSpecification.get(restTemplate.getRootUri() + "/v3/api-docs");

        // Then check status
        assertThat(response.getStatusCode()).isEqualTo(Status.OK.getStatusCode());

        // And check paths swagger
        List<String> expectedPaths = ImmutableList
                .copyOf(MAPPER.readTree(ResourceUtils.getFile("classpath:model/swagger.json")).get("paths").fieldNames());
        Iterable<String> paths = ImmutableList.copyOf(MAPPER.readTree(response.getBody().print()).get("paths").fieldNames());
        assertThat(paths).containsExactlyInAnyOrderElementsOf(expectedPaths);

    }

}
