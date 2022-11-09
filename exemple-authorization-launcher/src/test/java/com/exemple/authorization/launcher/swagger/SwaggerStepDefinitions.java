package com.exemple.authorization.launcher.swagger;

import static org.assertj.core.api.Assertions.assertThat;

import org.springframework.beans.factory.annotation.Autowired;

import com.exemple.authorization.launcher.common.JsonRestTemplate;
import com.exemple.authorization.launcher.core.IntegrationTestConfiguration;

import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

public class SwaggerStepDefinitions {

    @Autowired
    private SwaggerTestContext context;

    @When("get swagger schema")
    public void swagger() {

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).get("/v3/api-docs");

        context.setResponse(response);

    }

    @Then("schema status is {int}")
    public void checkStatus(int status) {

        assertThat(context.getResponse().getStatusCode()).isEqualTo(status);

    }

}
