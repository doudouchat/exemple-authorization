package com.exemple.authorization.launcher.api;

import static org.assertj.core.api.Assertions.assertThat;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;

import com.exemple.authorization.launcher.common.JsonRestTemplate;
import com.exemple.authorization.launcher.token.AuthorizationTestContext;

import io.cucumber.java.en.Then;
import io.restassured.response.Response;

public class ApiStepDefinitions {

    @Autowired
    private AuthorizationTestContext authorizationContext;

    @Then("account {string} is accessible")
    public void checkAccountIsAccessible(String username) {

        Response response = JsonRestTemplate.test()
                .header("Authorization", "Bearer " + authorizationContext.getAccessToken())
                .get("/account/" + username);

        assertThat(response.getStatusCode()).as("account is not accessible").isEqualTo(HttpStatus.OK.value());
    }

    @Then("account {string} is unauthorized")
    public void checkAccountIsUnauthorized(String username) {

        Response response = JsonRestTemplate.test()
                .header("Authorization", "Bearer " + authorizationContext.getAccessToken())
                .get("/account/" + username);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
    }

    @Then("account {string} is forbidden")
    public void checkAccountIsForbidden(String username) {

        Response response = JsonRestTemplate.test()
                .header("Authorization", "Bearer " + authorizationContext.getAccessToken())
                .get("/account/" + username);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
    }

    @Then("back is accessible")
    public void checkBackIsAccessible() {

        Response response = JsonRestTemplate.test()
                .header("Authorization", "Bearer " + authorizationContext.getAccessToken())
                .get("/back/123");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

    }
}
