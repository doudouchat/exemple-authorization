package com.exemple.authorization.integration.login;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import com.exemple.authorization.integration.common.JsonRestTemplate;
import com.exemple.authorization.integration.core.IntegrationTestConfiguration;

import io.restassured.http.ContentType;
import io.restassured.response.Response;

@SpringJUnitConfig(IntegrationTestConfiguration.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(OrderAnnotation.class)
class LoginIT {

    public static final String URL = "/ws/v1/logins";

    private static final String USERNAME = UUID.randomUUID() + "@gmail.com";

    private String accessAppToken = null;

    private String accessToken = null;

    @BeforeAll
    void init() {

        // When perform get access token

        Map<String, Object> params = Map.of("grant_type", "client_credentials");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).auth().basic("test", "secret")
                .formParams(params).post("/oauth/token");

        // Then check response

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

        accessAppToken = response.jsonPath().getString("access_token");
    }

    @Test
    @Order(0)
    void create() {

        // When perform post login

        Map<String, Object> body = Map.of("password", "mdp");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.JSON)
                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_USER)
                .header("Authorization", "Bearer " + accessAppToken)
                .body(body).put(LoginDisconnectionIT.URL + "/" + USERNAME);

        // Then check response

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED.value());

    }

    @Test
    @Order(1)
    void connection() {

        // When perform get access token

        Map<String, Object> params = Map.of(
                "grant_type", "password",
                "username", "jean.dupond@gmail.com",
                "password", "123",
                "client_id", "test_user",
                "redirect_uri", "xxx");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).auth()
                .basic("test_user", "secret").formParams(params).post("/oauth/token");

        // Then check response

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

        accessToken = response.jsonPath().getString("access_token");

    }

    @Test
    @Order(2)
    void head() {

        // When perform head login

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.JSON)
                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_USER)
                .header("Authorization", "Bearer " + accessToken)
                .head(LoginIT.URL + "/" + USERNAME);

        // Then check response

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT.value());

    }

    @Test
    void disable() {

        // When perform get access token

        Map<String, Object> params = Map.of(
                "grant_type", "password",
                "username", "jean.dupont@gmail.com",
                "password", "mdp",
                "client_id", "test_user",
                "redirect_uri", "xxx");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).auth()
                .basic("test_user", "secret")
                .formParams(params).post("/oauth/token");

        // Then check response

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());

    }
}
