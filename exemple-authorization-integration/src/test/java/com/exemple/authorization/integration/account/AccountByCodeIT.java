package com.exemple.authorization.integration.account;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.annotations.Test;

import com.exemple.authorization.integration.common.JsonRestTemplate;
import com.exemple.authorization.integration.core.IntegrationTestConfiguration;

import io.restassured.http.ContentType;
import io.restassured.response.Response;

@ContextConfiguration(classes = IntegrationTestConfiguration.class)
public class AccountByCodeIT extends AbstractTestNGSpringContextTests {

    private String accessToken = null;

    private String accessAppToken = null;

    @Test
    public void credentials() {

        Map<String, Object> params = new HashMap<>();
        params.put("grant_type", "client_credentials");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).auth().basic("test", "secret")
                .formParams(params).post("/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));
        assertThat(response.jsonPath().getString("access_token"), is(notNullValue()));

        accessAppToken = response.jsonPath().getString("access_token");

    }

    @Test(dependsOnMethods = "credentials")
    public void connection() {

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC)

                .header("Authorization", "Bearer " + accessAppToken)

                .formParams("username", "jean.dupond@gmail.com", "password", "123")

                .post("/login");

        assertThat(response.getStatusCode(), is(HttpStatus.FOUND.value()));

        String xAuthToken = response.getHeader("X-Auth-Token");
        assertThat(xAuthToken, is(notNullValue()));

        response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).redirects().follow(false)

                .header("X-Auth-Token", xAuthToken)

                .queryParam("response_type", "code")

                .queryParam("client_id", "test_user")

                .queryParam("scope", "account")

                .queryParam("state", "123")

                .get("/oauth/authorize");

        assertThat(response.getStatusCode(), is(HttpStatus.SEE_OTHER.value()));

        String location = response.getHeader(HttpHeaders.LOCATION);
        assertThat(location, is(notNullValue()));

        Matcher locationMatcher = Pattern.compile(".*code=(\\w*)(&state=)?(.*)?", Pattern.DOTALL).matcher(location);
        assertThat(locationMatcher.lookingAt(), is(true));

        String code = locationMatcher.group(1);
        String state = locationMatcher.group(3);

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "authorization_code");
        params.put("code", code);
        params.put("client_id", "test_user");
        params.put("redirect_uri", "xxx");

        response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC)

                .auth().basic("test_user", "secret")

                .formParams(params).post("/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        accessToken = response.jsonPath().getString("access_token");
        assertThat(accessToken, is(notNullValue()));
        assertThat(state, is("123"));

    }

    @Test(dependsOnMethods = "connection")
    public void get() {

        Response response = JsonRestTemplate.given()

                .header("Authorization", "Bearer " + accessToken).get("/account/123");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

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

        Response response = JsonRestTemplate.given()

                .header("Authorization", "Bearer " + accessToken).get("/account/123");

        assertThat(response.getStatusCode(), is(HttpStatus.UNAUTHORIZED.value()));
    }

}
