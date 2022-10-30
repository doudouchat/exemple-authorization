package com.exemple.authorization.launcher.token;

import static org.assertj.core.api.Assertions.assertThat;

import org.springframework.stereotype.Component;

import io.cucumber.spring.ScenarioScope;
import io.restassured.response.Response;

@Component
@ScenarioScope
public class AuthorizationTestContext {

    private String accessToken;

    private Response response;

    public Response getResponse() {
        assertThat(response).as("no response").isNotNull();
        return response;
    }

    public void setResponse(Response response) {
        this.response = response;
    }

    public String getAccessToken() {
        assertThat(this.accessToken).as("no access token").isNotNull();
        return this.accessToken;
    }

    public void setAccessToken(String token) {
        this.accessToken = token;
    }

}
