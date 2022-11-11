package com.exemple.authorization.disconnection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;

import com.exemple.authorization.common.LoggingFilter;
import com.exemple.authorization.core.AuthorizationTestConfiguration;
import com.exemple.authorization.core.client.AuthorizationClientBuilder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(classes = { AuthorizationTestConfiguration.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
@Slf4j
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(OrderAnnotation.class)
class DisconnectionApiTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private JWSSigner algorithm;

    @Autowired
    private AuthorizationClientBuilder authorizationClientBuilder;

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

    private SignedJWT accessToken;

    @Order(0)
    @Test
    void disconnection() throws JOSEException {

        var payload = new JWTClaimsSet.Builder()
                .claim("authorities", new String[] { "ROLE_ACCOUNT" })
                .audience("app")
                .jwtID(UUID.randomUUID().toString())
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .claim("client_id", "clientId1")
                .build();

        accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "app")
                .post(restTemplate.getRootUri() + "/ws/v1/disconnection");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT.value());

    }

    @Order(1)
    @Test
    void checkToken() {

        Map<String, String> params = Map.of("token", accessToken.serialize());

        Response response = requestSpecification.auth().basic("resource", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/check_token");

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value()),
                () -> assertThat(response.jsonPath().getString("error")).isEqualTo("invalid_token"));

    }

}
