package com.exemple.authorization.launcher.swagger;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Iterator;

import org.springframework.beans.factory.annotation.Autowired;

import com.exemple.authorization.launcher.common.JsonRestTemplate;
import com.exemple.authorization.launcher.core.IntegrationTestConfiguration;

import io.cucumber.datatable.DataTable;
import io.cucumber.java.Transpose;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

public class SwaggerStepDefinitions {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private SwaggerTestContext context;

    @When("get swagger schema")
    public void swagger() {

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).get("/v3/api-docs");

        context.setResponse(response);

    }

    @When("schema contains paths")
    public void containsPath(@Transpose DataTable expectedPaths) {

        Iterator<JsonNode> paths = MAPPER.readTree(context.getResponse().print()).get("paths").iterator();
        assertThat(paths).toIterable().map(JsonNode::stringValue).containsExactlyInAnyOrderElementsOf(expectedPaths.asList());

    }

    @Then("schema status is {int}")
    public void checkStatus(int status) {

        assertThat(context.getResponse().getStatusCode()).isEqualTo(status);

    }

}
