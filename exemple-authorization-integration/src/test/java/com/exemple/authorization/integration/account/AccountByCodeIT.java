package com.exemple.authorization.integration.account;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.HttpHeaders;
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
class AccountByCodeIT {

    private String accessToken;

    private String accessAppToken;

    @Test
    @Order(0)
    void credentials() {

        // When perform get access token

        Map<String, Object> params = new HashMap<>();
        params.put("grant_type", "client_credentials");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).auth().basic("test", "secret")
                .formParams(params).post("/oauth/token");

        // Then check response

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

        accessAppToken = response.jsonPath().getString("access_token");

    }

    @Test
    @Order(1)
    void connection() {

        // When perform login

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC)
                .header("Authorization", "Bearer " + accessAppToken)
                .formParams("username", "jean.dupond@gmail.com", "password", "123")
                .post("/login");

        // Then check response

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value()),
                () -> assertThat(response.getHeader("X-Auth-Token")).isNotNull(),
                () -> assertThat(response.getCookies()).isEmpty());

        String xAuthToken = response.getHeader("X-Auth-Token");

        // And perform authorize

        Response responseAuthorize = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).redirects()
                .follow(false)
                .header("X-Auth-Token", xAuthToken)
                .queryParam("response_type", "code")
                .queryParam("client_id", "test_user")
                .queryParam("scope", "account")
                .queryParam("state", "123")
                .get("/oauth/authorize");

        assertAll(
                () -> assertThat(responseAuthorize.getStatusCode()).isEqualTo(HttpStatus.SEE_OTHER.value()),
                () -> assertThat(responseAuthorize.getHeader(HttpHeaders.LOCATION)).isNotNull());

        String location = responseAuthorize.getHeader(HttpHeaders.LOCATION);

        // And check location

        Matcher locationMatcher = Pattern.compile(".*code=(\\w*)(&state=)?(.*)?", Pattern.DOTALL).matcher(location);
        assertThat(locationMatcher.lookingAt()).isTrue();

        String code = locationMatcher.group(1);
        String state = locationMatcher.group(3);

        // And check state

        assertThat(state).isEqualTo("123");

        // And perform get access token

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "authorization_code");
        params.put("code", code);
        params.put("client_id", "test_user");
        params.put("redirect_uri", "xxx");

        Response responseToken = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC)
                .auth().basic("test_user", "secret")
                .formParams(params).post("/oauth/token");

        // And check response token

        assertAll(
                () -> assertThat(responseToken.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                () -> assertThat(responseToken.jsonPath().getString("access_token")).isNotNull());

        accessToken = responseToken.jsonPath().getString("access_token");

    }

    @Test
    @Order(2)
    void get() {

        // When perform get

        Response response = JsonRestTemplate.given()
                .header("Authorization", "Bearer " + accessToken).get("/account/123");

        // Then check response

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

    }

    @Test
    @Order(3)
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
    @Order(4)
    void getFailure() {

        // When perform get

        Response response = JsonRestTemplate.given()
                .header("Authorization", "Bearer " + accessToken).get("/account/123");

        // Then check response

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
    }

}
