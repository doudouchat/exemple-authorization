package com.exemple.authorization.integration.password;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.annotations.Test;

import com.exemple.authorization.integration.common.JsonRestTemplate;
import com.exemple.authorization.integration.core.IntegrationTestConfiguration;

import io.restassured.http.ContentType;
import io.restassured.response.Response;

@ContextConfiguration(classes = IntegrationTestConfiguration.class)
public class PasswordIT extends AbstractTestNGSpringContextTests {

    private String accessAppToken = null;

    private String accessToken = null;

    @Test
    void connexion() {

        Map<String, Object> params = new HashMap<>();
        params.put("grant_type", "client_credentials");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).auth().basic("admin", "secret")
                .formParams(params).post("/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        accessAppToken = response.jsonPath().getString("access_token");
        assertThat(accessAppToken, is(notNullValue()));

    }

    @Test(dependsOnMethods = "connexion")
    void password() {

        Map<String, Object> newPassword = new HashMap<>();
        newPassword.put("login", "jean.dupond@gmail.com");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.JSON)

                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_ADMIN)

                .header("Authorization", "Bearer " + accessAppToken)

                .body(newPassword).post("/ws/v1/new_password");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        accessToken = response.jsonPath().getString("token");
        assertThat(accessToken, is(notNullValue()));

    }

    @Test(dependsOnMethods = "password")
    void get() {

        Response response = JsonRestTemplate.given()

                .header("Authorization", "Bearer " + accessToken).post("/account");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

    }

}
