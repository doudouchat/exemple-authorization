package com.exemple.authorization.launcher.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.time.Duration;
import java.util.Map;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
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
    private KafkaConsumer<String, Map<String, Object>> consumerNewPassword;

    @Autowired
    private AuthorizationTestContext authorizationContext;

    @When("new password for {string}")
    public void password(String username) {

        Map<String, Object> newPassword = Map.of("login", username);

        Response response = JsonRestTemplate.authorization()
                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_USER)
                .header("Authorization", "Bearer " + authorizationContext.getAccessToken())
                .body(newPassword).post("/ws/v1/new_password");

        context.setResponse(response);

        assertThat(response.getStatusCode()).isEqualTo(204);

    }

    @When("change password {string} for username {string}")
    public void update(String password, String username) {

        Map<String, Object> body = Map.of("password", password);

        Response response = JsonRestTemplate.authorization()
                .header(IntegrationTestConfiguration.APP_HEADER, IntegrationTestConfiguration.APP_USER)
                .header("Authorization", "Bearer " + authorizationContext.getAccessToken())
                .body(body).put("/ws/v1/logins/" + username);

        assertThat(response.getStatusCode()).isEqualTo(204);

    }

    @And("get password token")
    public void getAccessToken() throws InterruptedException {

        ConsumerRecords<String, Map<String, Object>> records = consumerNewPassword.poll(Duration.ofSeconds(20));

        await().atMost(Duration.ofSeconds(20))
                .untilAsserted(() -> assertThat(records).extracting(ConsumerRecord::value).anyMatch(value -> value.containsKey("token")));

        authorizationContext.setAccessToken(records.iterator().next().value().get("token").toString());

    }
}
