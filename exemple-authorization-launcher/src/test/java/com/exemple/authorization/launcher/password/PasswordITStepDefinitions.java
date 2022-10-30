package com.exemple.authorization.launcher.password;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;

import com.exemple.authorization.launcher.common.JsonRestTemplate;
import com.exemple.authorization.launcher.core.IntegrationTestConfiguration;
import com.exemple.authorization.launcher.token.AuthorizationTestContext;

import io.cucumber.java.en.And;
import io.cucumber.java.en.When;
import io.restassured.response.Response;

public class PasswordITStepDefinitions {

    @Autowired
    private PasswordTestContext context;

    @Autowired
    private AuthorizationTestContext authorizationContext;

    @When("new password for {string}")
    public void password(String username) {

        Map<String, Object> newPassword = Map.of("login", username);

        Response response = JsonRestTemplate.authorization()
                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_ADMIN)
                .header("Authorization", "Bearer " + authorizationContext.getAccessToken())
                .body(newPassword).post("/ws/v1/new_password");

        context.setResponse(response);

        assertThat(response.getStatusCode()).isEqualTo(200);

    }

    @When("change password {string} for username {string} by admin")
    public void update(String password, String username) {

        Map<String, Object> body = Map.of("password", password);

        Response response = JsonRestTemplate.authorization()
                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_ADMIN)
                .header("Authorization", "Bearer " + authorizationContext.getAccessToken())
                .body(body).put("/ws/v1/logins/" + username);

        assertThat(response.getStatusCode()).isEqualTo(204);

    }

    @And("get password token")
    public void getAccessToken() {

        assertThat(context.getResponse().jsonPath().getString("token")).isNotNull();

        authorizationContext.setAccessToken(context.getResponse().jsonPath().getString("token"));

    }
}
