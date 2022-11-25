package com.exemple.authorization.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.ws.rs.core.SecurityContext;

import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.test.EmbeddedKafkaBroker;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import com.exemple.authorization.common.LoggingFilter;
import com.exemple.authorization.core.AuthorizationTestConfiguration;
import com.exemple.authorization.core.feature.FeatureTestConfiguration.TestFilter;
import com.exemple.authorization.resource.login.LoginResource;
import com.exemple.authorization.resource.login.model.LoginEntity;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(classes = { AuthorizationTestConfiguration.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
@Slf4j
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class NewPasswordApiTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private JWSSigner algorithm;

    @Autowired
    private TestFilter testFilter;

    @Autowired
    private LoginResource loginResource;

    @Autowired
    private Clock clock;

    @Autowired
    private RSAPublicKey publicKey;

    @Value("${authorization.password.expiryTime}")
    private long expiryTime;

    private RequestSpecification requestSpecification;

    @BeforeEach
    private void before() {

        Mockito.reset(loginResource);

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG));

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    @TestMethodOrder(OrderAnnotation.class)
    class Password {

        @Autowired
        private EmbeddedKafkaBroker embeddedKafka;

        @Autowired
        private Consumer<String, Map<String, Object>> consumerKafka;

        private String username;

        private String token;

        @BeforeAll
        void username() {

            username = "jean.dupond@gmail.com";
        }

        @BeforeAll
        void subscribeConsumer() {
            embeddedKafka.consumeFromAllEmbeddedTopics(consumerKafka);
        }

        @Test
        @Order(0)
        void password() throws JOSEException {

            // Given token

            var payload = new JWTClaimsSet.Builder()
                    .claim("authorities", new String[] { "ROLE_APP" })
                    .claim("client_id", "clientId1")
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(algorithm);

            // And mock login resource

            LoginEntity account = new LoginEntity();
            account.setUsername(username);

            Map<String, Object> newPassword = Map.of("login", username);

            Mockito.when(loginResource.get(username)).thenReturn(Optional.of(account));

            // When perform create password

            Response response = requestSpecification.contentType(ContentType.JSON)
                    .header("Authorization", "Bearer " + accessToken.serialize())
                    .header("app", "app")
                    .body(newPassword).post(restTemplate.getRootUri() + "/ws/v1/new_password");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT.value());

            // And check security context

            assertAll(
                    () -> assertThat(testFilter.context.getUserPrincipal().getName()).isEqualTo("clientId1"),
                    () -> assertThat(testFilter.context.isUserInRole("ROLE_APP")).isTrue(),
                    () -> assertThat(testFilter.context.isSecure()).isTrue(),
                    () -> assertThat(testFilter.context.getAuthenticationScheme()).isEqualTo(SecurityContext.BASIC_AUTH));

            // And check kafka message

            ConsumerRecords<String, Map<String, Object>> records = this.consumerKafka.poll(Duration.ofSeconds(1));
            await().untilAsserted(() -> assertThat(records).hasSize(1));
            ConsumerRecord<String, Map<String, Object>> record = records.iterator().next();
            assertThat(record.value()).hasFieldOrProperty("token");

            token = (String) record.value().get("token");

        }

        @Order(1)
        @Test
        void checkToken() throws ParseException {

            // When decode token

            NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();

            var payload = jwtDecoder.decode(token);

            // Then check payload

            assertAll(
                    () -> assertThat(payload.getSubject()).isEqualTo(username),
                    () -> assertThat(payload.getClaimAsStringList("authorities")).contains("ROLE_APP"),
                    () -> assertThat(payload.getClaimAsStringList("scope")).contains("login:read", "login:update"),
                    () -> assertThat(payload.getExpiresAt()).isEqualTo(clock.instant().plusSeconds(expiryTime)),
                    () -> assertThat(payload.getId()).isNotNull());

        }

        @Test
        void passwordButLoginIsNotFound() throws JOSEException {

            // Given token

            var payload = new JWTClaimsSet.Builder()
                    .claim("authorities", new String[] { "ROLE_APP" })
                    .claim("client_id", "clientId1")
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(algorithm);

            // And mock login resource

            Mockito.when(loginResource.get(username)).thenReturn(Optional.empty());

            // When perform create password

            Map<String, Object> newPassword = Map.of("login", username);
            Response response = requestSpecification.contentType(ContentType.JSON)
                    .header("Authorization", "Bearer " + accessToken.serialize())
                    .header("app", "app")
                    .body(newPassword).post(restTemplate.getRootUri() + "/ws/v1/new_password");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT.value());

            // And check security context

            assertAll(
                    () -> assertThat(testFilter.context.getUserPrincipal().getName()).isEqualTo("clientId1"),
                    () -> assertThat(testFilter.context.isUserInRole("ROLE_APP")).isTrue(),
                    () -> assertThat(testFilter.context.isSecure()).isTrue(),
                    () -> assertThat(testFilter.context.getAuthenticationScheme()).isEqualTo(SecurityContext.BASIC_AUTH));

            // And check kafka message

            ConsumerRecords<String, Map<String, Object>> records = this.consumerKafka.poll(Duration.ofSeconds(1));
            await().during(Duration.ofSeconds(1)).untilAsserted(() -> assertThat(records).isEmpty());

        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    @TestMethodOrder(OrderAnnotation.class)
    class TrustedPassword {

        private String username;

        private String token;

        @BeforeAll
        void username() {

            username = "jean.dupond@gmail.com";
        }

        @Order(0)
        @Test
        void passwordTrustedClient() throws JOSEException {

            // Given token

            var payload = new JWTClaimsSet.Builder()
                    .claim("authorities", new String[] { "ROLE_TRUSTED_CLIENT" })
                    .claim("client_id", "clientId1")
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(algorithm);

            // And mock login resource

            LoginEntity account = new LoginEntity();
            account.setUsername(username);

            Map<String, Object> newPassword = Map.of("login", username);

            Mockito.when(loginResource.get(username)).thenReturn(Optional.of(account));

            // When perform create password

            Response response = requestSpecification.contentType(ContentType.JSON)
                    .header("Authorization", "Bearer " + accessToken.serialize())
                    .header("app", "app")
                    .body(newPassword).post(restTemplate.getRootUri() + "/ws/v1/new_password");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                    () -> assertThat(response.jsonPath().getString("token")).isNotNull());

            // And check security context

            assertAll(
                    () -> assertThat(testFilter.context.getUserPrincipal().getName()).isEqualTo("clientId1"),
                    () -> assertThat(testFilter.context.isUserInRole("ROLE_TRUSTED_CLIENT")).isTrue(),
                    () -> assertThat(testFilter.context.isSecure()).isTrue(),
                    () -> assertThat(testFilter.context.getAuthenticationScheme()).isEqualTo(SecurityContext.BASIC_AUTH));

            token = response.jsonPath().getString("token");

        }

        @Order(1)
        @Test
        void checkToken() throws ParseException {

            // When decode token

            NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();

            var payload = jwtDecoder.decode(token);

            // Then check payload

            assertAll(
                    () -> assertThat(payload.getSubject()).isEqualTo(username),
                    () -> assertThat(payload.getClaimAsStringList("authorities")).contains("ROLE_TRUSTED_CLIENT"),
                    () -> assertThat(payload.getClaimAsStringList("scope")).contains("login:read", "login:update"),
                    () -> assertThat(payload.getExpiresAt()).isEqualTo(Instant.now(clock).plusSeconds(expiryTime)),
                    () -> assertThat(payload.getId()).isNotNull());

        }

        @Test
        void passwordTrustedClientButLoginIsNotFound() throws JOSEException {

            // Given token

            var payload = new JWTClaimsSet.Builder()
                    .claim("authorities", new String[] { "ROLE_TRUSTED_CLIENT" })
                    .claim("client_id", "clientId1")
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(algorithm);

            // And mock login resource

            Mockito.when(loginResource.get(username)).thenReturn(Optional.empty());

            // When perform create password

            Map<String, Object> newPassword = Map.of("login", username);
            Response response = requestSpecification.contentType(ContentType.JSON)
                    .header("Authorization", "Bearer " + accessToken.serialize())
                    .header("app", "app")
                    .body(newPassword).post(restTemplate.getRootUri() + "/ws/v1/new_password");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                    () -> assertThat(response.getBody().asString()).isEqualTo("{}"));

        }

    }

}
