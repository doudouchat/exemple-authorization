package com.exemple.authorization.launcher.jwks;

import static org.assertj.core.api.Assertions.assertThat;

import org.springframework.beans.factory.annotation.Autowired;

import com.exemple.authorization.launcher.common.JsonRestTemplate;
import com.exemple.authorization.launcher.core.IntegrationTestConfiguration;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

public class JwksStepDefinitions {

    @Autowired
    private JwksTestContext context;

    @When("get jwks")
    public void jwks() {

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).get("/.well-known/jwks.json");

        context.setResponse(response);

    }

    @Then("jwks status is {int}")
    public void checkStatus(int status) {

        assertThat(context.getResponse().getStatusCode()).isEqualTo(status);

    }

    @And("first kid is {string}")
    public void checkStatus(String kid) {

        assertThat(context.getResponse().jsonPath().getString("keys[0].kid")).isEqualTo(kid);

    }

}
