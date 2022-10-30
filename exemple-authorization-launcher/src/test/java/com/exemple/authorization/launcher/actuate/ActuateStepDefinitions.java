package com.exemple.authorization.launcher.actuate;

import static org.assertj.core.api.Assertions.assertThat;

import org.springframework.beans.factory.annotation.Autowired;

import com.exemple.authorization.launcher.common.JsonRestTemplate;
import com.exemple.authorization.launcher.core.IntegrationTestConfiguration;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

public class ActuateStepDefinitions {

    @Autowired
    private ActuateTestContext context;

    @When("get info")
    public void info() {

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).get("/actuator/info");

        context.setResponse(response);

    }

    @Then("actuate status is {int}")
    public void checkStatus(int status) {

        assertThat(context.getResponse().getStatusCode()).isEqualTo(status);

    }

    @And("actuate property {string} exists")
    public void checkProperty(String property) {

        assertThat(context.getResponse().jsonPath().getString(property)).as("actuate property %s not exists", property).isNotNull();

    }

}
