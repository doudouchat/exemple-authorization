package com.exemple.authorization.launcher.actuate;

import static org.assertj.core.api.Assertions.assertThat;

import org.springframework.stereotype.Component;

import io.cucumber.spring.ScenarioScope;
import io.restassured.response.Response;

@Component
@ScenarioScope
public class ActuateTestContext {

    private Response response;

    public Response getResponse() {
        assertThat(response).as("no response").isNotNull();
        return response;
    }

    public void setResponse(Response response) {
        this.response = response;
    }

}
