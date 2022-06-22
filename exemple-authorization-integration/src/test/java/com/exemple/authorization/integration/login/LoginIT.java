package com.exemple.authorization.integration.login;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.exemple.authorization.integration.common.JsonRestTemplate;
import com.exemple.authorization.integration.core.IntegrationTestConfiguration;

import io.restassured.http.ContentType;
import io.restassured.response.Response;

@ContextConfiguration(classes = { IntegrationTestConfiguration.class })
public class LoginIT extends AbstractTestNGSpringContextTests {

    public static final String URL = "/ws/v1/logins";

    private static final String USERNAME = UUID.randomUUID() + "@gmail.com";

    private String accessToken = null;

    @BeforeClass
    public void init() {

        Map<String, Object> params = new HashMap<>();
        params.put("grant_type", "client_credentials");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).auth().basic("admin", "secret")
                .formParams(params).post("/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        String accessAppToken = response.jsonPath().getString("access_token");
        assertThat(accessAppToken, is(notNullValue()));

        Map<String, Object> newPassword = new HashMap<>();
        newPassword.put("login", USERNAME);

        response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.JSON)

                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_ADMIN)

                .header("Authorization", "Bearer " + accessAppToken)

                .body(newPassword).post("/ws/v1/new_password");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        accessToken = response.jsonPath().getString("token");
        assertThat(accessToken, is(notNullValue()));

    }

    @Test
    public void create() {

        Map<String, Object> body = new HashMap<>();
        body.put("password", "mdp");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.JSON)

                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_ADMIN)

                .header("Authorization", "Bearer " + accessToken)

                .body(body).put(LoginIT.URL + "/" + USERNAME);

        assertThat(response.getStatusCode(), is(HttpStatus.CREATED.value()));

    }

    @Test(dependsOnMethods = "create")
    public void connection() {

        Map<String, Object> params = new HashMap<>();
        params.put("grant_type", "password");
        params.put("username", USERNAME);
        params.put("password", "mdp");
        params.put("client_id", "test_user");
        params.put("redirect_uri", "xxx");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).auth()
                .basic("test_user", "secret").formParams(params).post("/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        accessToken = response.jsonPath().getString("access_token");
        assertThat(accessToken, is(notNullValue()));

    }

    @Test(dependsOnMethods = "create")
    public void head() {

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.JSON)

                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_USER)

                .header("Authorization", "Bearer " + accessToken)

                .head(LoginIT.URL + "/" + USERNAME);

        assertThat(response.getStatusCode(), is(HttpStatus.NO_CONTENT.value()));

    }

    @Test
    public void disable() {

        Map<String, Object> params = new HashMap<>();
        params.put("grant_type", "password");
        params.put("username", "jean.dupont@gmail.com");
        params.put("password", "mdp");
        params.put("client_id", "test_user");
        params.put("redirect_uri", "xxx");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).auth()
                .basic("test_user", "secret")
                .formParams(params).post("/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.BAD_REQUEST.value()));

    }
}
