package com.exemple.authorization.integration.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.util.HashMap;
import java.util.Map;

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
class PasswordIT {

    private String accessAppToken = null;

    private String accessToken = null;

    @Test
    @Order(0)
    void connexion() {

        // When perform get access token

        Map<String, Object> params = new HashMap<>();
        params.put("grant_type", "client_credentials");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).auth().basic("admin", "secret")
                .formParams(params).post("/oauth/token");

        // Then check response

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

        accessAppToken = response.jsonPath().getString("access_token");

    }

    @Test
    @Order(1)
    void password() {

        // When perform new password

        Map<String, Object> newPassword = new HashMap<>();
        newPassword.put("login", "jean.dupond@gmail.com");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.JSON)
                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_ADMIN)
                .header("Authorization", "Bearer " + accessAppToken)
                .body(newPassword).post("/ws/v1/new_password");

        // Then check response

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                () -> assertThat(response.jsonPath().getString("token")).isNotNull());

        accessToken = response.jsonPath().getString("token");

    }

    @Test
    @Order(2)
    void post() {

        // When perform post

        Response response = JsonRestTemplate.given()
                .header("Authorization", "Bearer " + accessToken).post("/account");

        // Then check response

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

    }

}
