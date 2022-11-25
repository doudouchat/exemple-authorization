package com.exemple.authorization.core.feature;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import javax.ws.rs.core.SecurityContext;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;

import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.exemple.authorization.common.LoggingFilter;
import com.exemple.authorization.core.AuthorizationTestConfiguration;
import com.exemple.authorization.core.feature.FeatureTestConfiguration.TestFilter;
import com.exemple.authorization.core.feature.authorization.AuthorizationFeatureConfiguration;
import com.hazelcast.core.HazelcastInstance;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
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
class AuthorizationFeatureTest {

    public static final RSAKey OTHER_RSA_KEY;

    static {

        try {
            OTHER_RSA_KEY = new RSAKeyGenerator(2048).keyUse(KeyUse.SIGNATURE).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }

    }

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private JWSSigner algorithm;

    @Autowired
    private ApplicationDetailService applicationDetailService;

    @Autowired
    private HazelcastInstance hazelcastInstance;

    @Autowired
    private TestFilter testFilter;

    private static final String URL = "/ws/v1/test";

    private RequestSpecification requestSpecification;

    @BeforeEach
    private void before() {

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG));
        testFilter.context = null;

    }

    @Test
    @DisplayName("fails because application is not found")
    void failsBecauseApplicationIsNotFound() throws JOSEException {

        // Given token

        var payload = new JWTClaimsSet.Builder()
                .subject("john_doe")
                .claim("client_id", "clientId1")
                .claim("scope", new String[] { "test:read" })
                .jwtID(UUID.randomUUID().toString())
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        // And mock application information

        Mockito.when(applicationDetailService.get("test")).thenReturn(Optional.empty());

        // When perform get

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "test")
                .get(restTemplate.getRootUri() + URL);

        // Then check status

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());

        // And check security context

        assertThat(testFilter.context).isNull();

        // And check body

        assertThat(response.body().asString()).isEqualTo("Access to test is forbidden");

    }

    @Test
    @DisplayName("fails because token client id and application are different")
    void failsBecauseTokenClientIdAndApplicationAreDifferent() throws JOSEException {

        // Given token

        var payload = new JWTClaimsSet.Builder()
                .subject("john_doe")
                .claim("client_id", "clientId1")
                .claim("scope", new String[] { "test:read" })
                .jwtID(UUID.randomUUID().toString())
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        // And mock application information

        Mockito.when(applicationDetailService.get("other")).thenReturn(Optional.of(ApplicationDetail.builder().clientId("test").build()));

        // When perform get

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "other")
                .get(restTemplate.getRootUri() + URL);

        // Then check status

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());

        // And check security context

        assertThat(testFilter.context).isNull();

        // And check body

        assertThat(response.body().asString()).isEqualTo("Access to clientId1 is forbidden");

    }

    @Test
    @DisplayName("fails because token is in black list")
    void failsBecauseTokenIsInBlackList() throws JOSEException {

        // Given token

        String deprecatedTokenId = UUID.randomUUID().toString();
        hazelcastInstance.getMap(AuthorizationFeatureConfiguration.TOKEN_BLACK_LIST).put(deprecatedTokenId, Date.from(Instant.now()));

        var payload = new JWTClaimsSet.Builder()
                .subject("john_doe")
                .claim("client_id", "clientId1")
                .claim("scope", new String[] { "test:read" })
                .jwtID(deprecatedTokenId)
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        // When perform get

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "app")
                .get(restTemplate.getRootUri() + URL);

        // Then check status

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());

        // And check security context

        assertThat(testFilter.context).isNull();

        // And check body

        assertThat(response.body().asString()).endsWith(deprecatedTokenId + " has been excluded");

    }

    @Test
    @DisplayName("fails because public key doesn't check signature")
    void failsBecausePublicKeyDoesntCheckSignature() throws JOSEException {

        // Given token

        var payload = new JWTClaimsSet.Builder()
                .claim("client_id", "clientId1")
                .subject("john_doe")
                .claim("scope", new String[] { "test:read" })
                .jwtID(UUID.randomUUID().toString())
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(new RSASSASigner(OTHER_RSA_KEY));

        // When perform get

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "app")
                .get(restTemplate.getRootUri() + URL);

        // Then check status

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());

        // And check security context

        assertThat(testFilter.context).isNull();

        // And check body

        assertThat(response.body().asString()).endsWith("Invalid signature");

    }

    @Test
    @DisplayName("fails because public token is deprecated")
    void failsBecauseTokenIsDeprecated() throws JOSEException {

        // Given token

        var payload = new JWTClaimsSet.Builder()
                .subject("john_doe")
                .claim("client_id", "clientId1")
                .claim("scope", new String[] { "test:read" })
                .expirationTime(Date.from(Instant.now().minusSeconds(1)))
                .jwtID(UUID.randomUUID().toString())
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        // When perform get

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "clientId1")
                .get(restTemplate.getRootUri() + URL);

        // Then check status

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());

        // And check security context

        assertThat(testFilter.context).isNull();

        // And check body

        assertThat(response.body().asString()).contains("Jwt expired at ");

    }

    @Test
    @DisplayName("fails because public token is missing")
    void failsBecauseTokenIsMissing() {

        // When perform get

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("app", "clientId1")
                .get(restTemplate.getRootUri() + URL);

        // Then check status

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());

        // And check security context

        assertThat(testFilter.context).isNull();

    }

    @Test
    void success() throws JOSEException {

        // Given token

        var payload = new JWTClaimsSet.Builder()
                .subject("john_doe")
                .claim("client_id", "clientId1")
                .claim("scope", new String[] { "test:read" })
                .jwtID(UUID.randomUUID().toString())
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        // When perform get

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "clientId1")
                .get(restTemplate.getRootUri() + URL);

        // Then check status

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

        // And check security context

        assertAll(
                () -> assertThat(testFilter.context.getUserPrincipal().getName()).isEqualTo("john_doe"),
                () -> assertThat(testFilter.context.isSecure()).isTrue(),
                () -> assertThat(testFilter.context.getAuthenticationScheme()).isEqualTo(SecurityContext.BASIC_AUTH));

    }

}
