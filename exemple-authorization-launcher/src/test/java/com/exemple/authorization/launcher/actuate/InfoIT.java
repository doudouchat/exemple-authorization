package com.exemple.authorization.launcher.actuate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import com.exemple.authorization.launcher.common.JsonRestTemplate;
import com.exemple.authorization.launcher.core.IntegrationTestConfiguration;

import io.restassured.http.ContentType;
import io.restassured.response.Response;

class InfoIT {

    @Test
    void info() {

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).get("/actuator/info");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));
        assertThat(response.jsonPath().getString("version"), is(notNullValue()));
        assertThat(response.jsonPath().getString("buildTime"), is(notNullValue()));

    }

}
