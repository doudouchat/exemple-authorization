package com.exemple.authorization.integration.login;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

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
public class LoginDisconnectionIT extends AbstractTestNGSpringContextTests {

    public static final String URL = "/ws/v1/logins";

    private static final String USERNAME = UUID.randomUUID() + "@gmail.com";

    private String accessAppToken = null;

    private String accessToken = null;

    @BeforeClass
    public void init() {

        Map<String, Object> params = new HashMap<>();
        params.put("grant_type", "client_credentials");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).auth().basic("test", "secret")
                .formParams(params).post("/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        accessAppToken = response.jsonPath().getString("access_token");
        assertThat(accessAppToken, is(notNullValue()));

    }

    @Test
    public void create() {

        Map<String, Object> body = new HashMap<>();
        body.put("password", "mdp");
        body.put("roles", new String[] { "ROLE_ACCOUNT" });

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.JSON)

                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_USER)

                .header("Authorization", "Bearer " + accessAppToken)

                .body(body).put(LoginDisconnectionIT.URL + "/" + USERNAME);

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
    public void get() {

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.JSON)

                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_USER)

                .header("Authorization", "Bearer " + accessToken)

                .get(LoginDisconnectionIT.URL + "/" + USERNAME);

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        assertThat(response.jsonPath().get("password"), is(nullValue()));
        assertThat(response.jsonPath().getString("username"), is(nullValue()));
        assertThat(response.jsonPath().getString("disabled"), is("false"));
        assertThat(response.jsonPath().getString("accountLocked"), is("false"));

    }

    @Test(dependsOnMethods = "get")
    public void disconnection() {

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.JSON)

                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_USER)

                .header("Authorization", "Bearer " + accessToken)

                .post("/ws/v1/disconnection");

        assertThat(response.getStatusCode(), is(HttpStatus.NO_CONTENT.value()));

    }

    @Test(dependsOnMethods = "disconnection")
    public void getFailure() {

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.JSON)

                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_USER)

                .header("Authorization", "Bearer " + accessToken)

                .get(LoginDisconnectionIT.URL + "/" + USERNAME);

        assertThat(response.getStatusCode(), is(HttpStatus.UNAUTHORIZED.value()));
    }

}
