package com.exemple.authorization.launcher.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;

import com.exemple.authorization.launcher.common.JsonRestTemplate;
import com.exemple.authorization.launcher.core.IntegrationTestConfiguration;

import io.cucumber.datatable.DataTable;
import io.cucumber.java.Transpose;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.When;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

public class AuthorizationStepDefinitions {

    @Autowired
    private AuthorizationTestContext context;

    @Given("get access token by client credentials to {string} and scopes {string}")
    public void tokenByClientCredentials(String client, String scope) {

        Map<String, Object> params = Map.of(
                "grant_type", "client_credentials",
                "scope", scope);

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC)
                .header("Authorization", "Basic " + Base64.encodeBase64String((client + ":secret").getBytes(StandardCharsets.UTF_8)))
                .formParams(params).post("/oauth/token");

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

        context.setAccessToken(response.jsonPath().getString("access_token"));

    }

    @Given("get access token by password for username {string} and password {string}")
    @Given("connect to {string} and password {string}")
    public void tokenByPassword(String username, String password) {

        Map<String, Object> params = Map.of(
                "grant_type", "password",
                "username", username,
                "password", password,
                "client_id", "test_user",
                "redirect_uri", "http://xxx");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC)
                .header("Authorization", "Basic " + Base64.encodeBase64String("test_user:secret".getBytes(StandardCharsets.UTF_8)))
                .formParams(params)
                .post("/oauth/token");

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

        context.setAccessToken(response.jsonPath().getString("access_token"));
        context.setResponse(response);

    }

    @Given("get access token by password for username {string} and password {string} is bad")
    public void tokenByPasswordIsBad(String username, String password) {

        Map<String, Object> params = Map.of(
                "grant_type", "password",
                "username", username,
                "password", password,
                "client_id", "test_user",
                "redirect_uri", "http://xxx");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC)
                .header("Authorization", "Basic " + Base64.encodeBase64String("test_user:secret".getBytes(StandardCharsets.UTF_8)))
                .formParams(params)
                .post("/oauth/token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());

    }

    @Given("get access token by password for username {string} and password {string} is unauthorized")
    public void tokenByPasswordIsUnauthorized(String username, String password) {

        Map<String, Object> params = Map.of(
                "grant_type", "password",
                "username", username,
                "password", password,
                "client_id", "test_user",
                "redirect_uri", "http://xxx");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC)
                .header("Authorization", "Basic " + Base64.encodeBase64String("test_user:secret".getBytes(StandardCharsets.UTF_8)))
                .formParams(params)
                .post("/oauth/token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());

    }

    @Given("get access token by password for back {string} and password {string}")
    public void tokenByPasswordForBack(String back, String password) {

        Map<String, Object> params = Map.of(
                "grant_type", "password",
                "username", back,
                "password", password,
                "client_id", "back_user",
                "redirect_uri", "http://xxx");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC)
                .header("Authorization", "Basic " + Base64.encodeBase64String("back_user:secret".getBytes(StandardCharsets.UTF_8)))
                .formParams(params)
                .post("/oauth/token");

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

        context.setAccessToken(response.jsonPath().getString("access_token"));
        context.setResponse(response);

    }

    @Given("login to {string} and password {string}")
    public void login(String username, String password) {

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC)
                .header("App", "test")
                .header("Authorization", "Bearer " + context.getAccessToken())
                .formParams("username", username, "password", password)
                .post("/login");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value());

        context.setResponse(response);

    }

    @Given("login to {string} and password {string} is bad")
    public void loginIsBad(String username, String password) {

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC)
                .header("App", "test")
                .header("Authorization", "Bearer " + context.getAccessToken())
                .formParams("username", username, "password", password)
                .post("/login");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());

    }

    @Given("login to {string} and password {string} is unauthorized")
    public void loginIsUnauthorized(String username, String password) {

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC)
                .header("App", "test")
                .header("Authorization", "Bearer " + context.getAccessToken())
                .formParams("username", username, "password", password)
                .post("/login");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());

    }

    @And("authorize")
    public void authorize(@Transpose DataTable scopes) {

        assertThat(context.getResponse().getHeader("X-Auth-Token")).isNotNull();

        String xAuthToken = context.getResponse().getHeader("X-Auth-Token");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).redirects()
                .follow(false)
                .header("X-Auth-Token", xAuthToken)
                .queryParam("response_type", "code")
                .queryParam("client_id", "test_user")
                .queryParam("scope", scopes.column(0).stream().collect(Collectors.joining(" ")))
                .get("/oauth/authorize");
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value());

        context.setResponse(response);

    }

    @And("authorize implicit")
    public void authorizeImplict() {

        assertThat(context.getResponse().getHeader("X-Auth-Token")).isNotNull();

        String xAuthToken = context.getResponse().getHeader("X-Auth-Token");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).redirects()
                .follow(false)
                .header("X-Auth-Token", xAuthToken)
                .queryParam("response_type", "token")
                .queryParam("client_id", "test_user")
                .get("/oauth/authorize");

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value()),
                () -> assertThat(response.getHeader(HttpHeaders.LOCATION)).isNotNull());

        String location = response.getHeader(HttpHeaders.LOCATION);

        String accessToken = location.split("#|=|&")[2];
        assertThat(accessToken).isNotNull();

        context.setAccessToken(accessToken);
        context.setResponse(response);

    }

    @And("get access token by code")
    public void tokenByCode() {

        assertThat(context.getResponse().getHeader(HttpHeaders.LOCATION)).isNotNull();

        String location = context.getResponse().getHeader(HttpHeaders.LOCATION);

        Matcher locationMatcher = Pattern.compile(".*code=([a-zA-Z0-9\\-_]*)(&state=)?(.*)?", Pattern.DOTALL).matcher(location);
        assertThat(locationMatcher.lookingAt()).as("location %s is unexpected", location).isTrue();

        String code = locationMatcher.group(1);

        Map<String, String> params = Map.of(
                "grant_type", "authorization_code",
                "code", code,
                "client_id", "test_user",
                "redirect_uri", "/ws/test");

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC)
                .header("Authorization", "Basic " + Base64.encodeBase64String("test_user:secret".getBytes(StandardCharsets.UTF_8)))
                .formParams(params)
                .post("/oauth/token");

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

        context.setAccessToken(response.jsonPath().getString("access_token"));
        context.setResponse(response);

    }

    @And("refresh access token")
    public void refreshToken() {

        String refreshToken = context.getResponse().jsonPath().getString("refresh_token");

        Map<String, String> params = Map.of(
                "grant_type", "refresh_token",
                "client_id", "test_user",
                "refresh_token", refreshToken);

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC)
                .header("Authorization", "Basic " + Base64.encodeBase64String("test_user:secret".getBytes(StandardCharsets.UTF_8)))
                .formParams(params)
                .post("/oauth/token");

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

        context.setAccessToken(response.jsonPath().getString("access_token"));
    }

    @When("disconnection")
    public void disconnection() {

        Map<String, String> params = Map.of("token", context.getAccessToken());

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC)
                .formParams(params)
                .post("/oauth/revoke_token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

    }

}
