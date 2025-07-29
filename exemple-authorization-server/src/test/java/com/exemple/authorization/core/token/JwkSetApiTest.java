package com.exemple.authorization.core.token;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;

import com.exemple.authorization.common.LoggingFilter;
import com.exemple.authorization.core.AuthorizationTestConfiguration;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(classes = { AuthorizationTestConfiguration.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
@Slf4j
@ActiveProfiles("test")
class JwkSetApiTest {

    @LocalServerPort
    protected int localPort;

    private RequestSpecification requestSpecification;

    @BeforeEach
    void before() {

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG)).port(localPort);

    }

    @Test
    void publicKeys() {

        Response response = requestSpecification.get("/oauth/jwks");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));
        assertThat(response.jsonPath().get("keys[0].kid"), is("exemple-key-id"));

    }

}
