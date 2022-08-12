package com.exemple.authorization.integration.account;

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
class AccountByPasswordIT {

    private String accessToken;

    @Test
    @Order(0)
    void connection() {

        // When perform get access token

        Map<String, Object> params = new HashMap<>();
        params.put("grant_type", "password");
        params.put("username", "jean.dupond@gmail.com");
        params.put("password", "123");
        params.put("client_id", "test_user");
        params.put("redirect_uri", "xxx");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).auth()
                .basic("test_user", "secret").formParams(params).post("/oauth/token");

        // Then check response

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

        accessToken = response.jsonPath().getString("access_token");

    }

    @Test
    @Order(1)
    void get() {

        // When perform get

        Response response = JsonRestTemplate.given()
                .header("Authorization", "Bearer " + accessToken).get("/account/123");

        // Then check response

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

    }

    @Test
    @Order(2)
    void disconnection() {

        // When perform disconnection

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.JSON)
                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_USER)
                .header("Authorization", "Bearer " + accessToken)
                .post("/ws/v1/disconnection");

        // Then check response

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT.value());

    }

    @Test
    @Order(3)
    void getFailure() {

        // When perform get

        Response response = JsonRestTemplate.given()
                .header("Authorization", "Bearer " + accessToken).get("/account/123");

        // Then check response

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());

    }

}
