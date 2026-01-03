package com.exemple.authorization.launcher.login;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;

import com.exemple.authorization.launcher.common.JsonRestTemplate;
import com.exemple.authorization.launcher.core.IntegrationTestConfiguration;
import com.exemple.authorization.launcher.token.AuthorizationTestContext;

import io.cucumber.java.en.And;
import io.cucumber.java.en.When;
import io.restassured.response.Response;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

public class LoginITStepDefinitions {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private AuthorizationTestContext authorizationContext;

    @When("new username {string} with password {string}")
    public void newUsername(String username, String password) {

        Map<String, Object> body = Map.of("password", password);

        Response response = JsonRestTemplate.authorization()
                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_USER)
                .header("Authorization", "Bearer " + authorizationContext.getAccessToken())
                .body(body).put("/ws/v1/logins/" + username);

        assertThat(response.getStatusCode()).isEqualTo(201);

    }

    @And("username {string} exists")
    public void checkUsername(String username) {

        Response response = JsonRestTemplate.authorization()
                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_USER)
                .header("Authorization", "Bearer " + authorizationContext.getAccessToken())
                .head("/ws/v1/logins/" + username);

        assertThat(response.getStatusCode()).as("username %s not accessible", username).isEqualTo(HttpStatus.NO_CONTENT.value());

    }

    @And("change username from {string} to {string}")
    public void changeUsername(String fromUsername, String toUsername) {

        Map<String, Object> body = Map.of("toUsername", toUsername, "fromUsername", fromUsername);

        Response response = JsonRestTemplate.authorization()
                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_USER)
                .header("Authorization", "Bearer " + authorizationContext.getAccessToken())
                .body(body).post("/ws/v1/logins/move");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED.value());

    }

    @And("change username from {string} to {string} fails because")
    public void changeUsername(String fromUsername, String toUsername, JsonNode error) {

        Map<String, Object> body = Map.of("toUsername", toUsername, "fromUsername", fromUsername);

        Response response = JsonRestTemplate.authorization()
                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_USER)
                .header("Authorization", "Bearer " + authorizationContext.getAccessToken())
                .body(body).post("/ws/v1/logins/move");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(MAPPER.readTree(response.asString())).isEqualTo(error);

    }

}
