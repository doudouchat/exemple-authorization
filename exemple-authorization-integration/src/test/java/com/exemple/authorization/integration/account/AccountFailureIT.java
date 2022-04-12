package com.exemple.authorization.integration.account;

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
public class AccountFailureIT extends AbstractTestNGSpringContextTests {

    @Test
    public void getForbidden() {

        Map<String, Object> params = new HashMap<>();
        params.put("grant_type", "password");
        params.put("username", "admin");
        params.put("password", "admin123");
        params.put("client_id", "back_user");
        params.put("redirect_uri", "xxx");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).auth()
                .basic("back_user", "secret").formParams(params).post("/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        String accessToken = response.jsonPath().getString("access_token");
        assertThat(accessToken, is(notNullValue()));

        response = JsonRestTemplate.given()

                .header("Authorization", "Bearer " + accessToken).get("/account/123");

        assertThat(response.getStatusCode(), is(HttpStatus.FORBIDDEN.value()));

    }

    @Test
    public void connectionFailure() {

        Map<String, Object> params = new HashMap<>();
        params.put("grant_type", "password");
        params.put("username", "jean.dupont@gmail.com");
        params.put("password", "124");
        params.put("client_id", "test_user");
        params.put("redirect_uri", "xxx");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).auth()
                .basic("test_user", "secret").formParams(params).post("/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.UNAUTHORIZED.value()));
    }

}
