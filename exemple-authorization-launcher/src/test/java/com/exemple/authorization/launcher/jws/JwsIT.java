package com.exemple.authorization.launcher.jws;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import com.exemple.authorization.launcher.common.JsonRestTemplate;
import com.exemple.authorization.launcher.core.IntegrationTestConfiguration;

import io.restassured.http.ContentType;
import io.restassured.response.Response;

@SpringJUnitConfig(IntegrationTestConfiguration.class)
class JwsIT {

    @Test
    void publicKeys() {

        // When perform public keys

        Response response = JsonRestTemplate.given(IntegrationTestConfiguration.AUTHORIZATION_URL, ContentType.URLENC).get("/.well-known/jwks.json");

        // Then check response

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                () -> assertThat(response.jsonPath().getString("keys[0].kid")).isEqualTo("exemple-key-id"));

    }

}
