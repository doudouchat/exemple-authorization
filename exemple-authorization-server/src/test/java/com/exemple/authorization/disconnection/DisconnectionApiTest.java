package com.exemple.authorization.disconnection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.exemple.authorization.common.LoggingFilter;
import com.exemple.authorization.core.AuthorizationTestConfiguration;
import com.exemple.authorization.core.client.AuthorizationClientBuilder;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(classes = { AuthorizationTestConfiguration.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
@Slf4j
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DisconnectionApiTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private AuthorizationClientBuilder authorizationClientBuilder;

    @Autowired
    private Algorithm algorithm;

    @Value("${authorization.password.expiryTime}")
    private long expiryTime;

    private RequestSpecification requestSpecification;

    @BeforeAll
    private void init() throws Exception {

        String password = "{bcrypt}" + BCrypt.hashpw("secret", BCrypt.gensalt());

        authorizationClientBuilder

                .withClient("test").secret(password).authorizedGrantTypes("client_credentials").redirectUris("xxx").scopes("account:create")
                .autoApprove("account:create").authorities("ROLE_APP").resourceIds("app1")

                .and()

                .withClient("resource").secret(password).authorizedGrantTypes("client_credentials").authorities("ROLE_TRUSTED_CLIENT")

                .and().build();

    }

    @BeforeEach
    private void before() {

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG));

    }

    private String accessToken;

    @Order(0)
    @Test
    void disconnection() {

        accessToken = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_ACCOUNT" }).withAudience("app")
                .withJWTId(UUID.randomUUID().toString()).withExpiresAt(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .withClaim("client_id", "clientId1").sign(algorithm);

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .post(restTemplate.getRootUri() + "/ws/v1/disconnection");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT.value());

    }

    private Stream<Arguments> disconnectionFailure() {

        String accessToken1 = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_ACCOUNT" }).withAudience("app")
                .withExpiresAt(Date.from(Instant.now().plus(1, ChronoUnit.DAYS))).withClaim("client_id", "clientId1").sign(algorithm);

        String accessToken2 = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_ACCOUNT" }).withAudience("app")
                .withJWTId(UUID.randomUUID().toString()).withClaim("client_id", "clientId1").sign(algorithm);

        return Stream.of(
                // no jti
                Arguments.of(accessToken1),
                // no exp
                Arguments.of(accessToken2)

        );
    }

    @ParameterizedTest
    @MethodSource
    void disconnectionFailure(String accessToken) {

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .post(restTemplate.getRootUri() + "/ws/v1/disconnection");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());

    }

    @Order(1)
    @Test
    void checkToken() {

        Map<String, String> params = new HashMap<>();
        params.put("token", accessToken);

        Response response = requestSpecification.auth().basic("resource", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/check_token");

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value()),
                () -> assertThat(response.jsonPath().getString("error")).isEqualTo("invalid_token"));

    }

}
