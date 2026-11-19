package com.exemple.authorization.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.ActiveProfiles;

import com.exemple.authorization.AuthorizationJwtConfiguration;
import com.exemple.authorization.common.LoggingFilter;
import com.exemple.authorization.resource.login.LoginResource;
import com.exemple.authorization.resource.login.model.LoginEntity;
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
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(classes = { AuthorizationTestConfiguration.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Slf4j
@ActiveProfiles("test")
class AuthorizationServerTest {

    private static final RSAKey OTHER_RSA_KEY;

    static {

        try {
            OTHER_RSA_KEY = new RSAKeyGenerator(2048).keyUse(KeyUse.SIGNATURE).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }

    }

    @LocalServerPort
    protected int localPort;

    @Autowired
    private JWSSigner algorithm;

    @Autowired
    private LoginResource resource;

    @Autowired
    @Qualifier("hazelcastClient")
    private HazelcastInstance client;

    private RequestSpecification requestSpecification;

    private static final Pattern LOCATION;

    static {

        LOCATION = Pattern.compile(".*code=([a-zA-Z0-9\\-_]*)(&state=)?(.*)?", Pattern.DOTALL);
    }

    @BeforeEach
    void before() {

        reset(resource);

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG)).port(localPort);

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    @TestMethodOrder(OrderAnnotation.class)
    class AuthorizationByCode {

        @Nested
        @TestInstance(TestInstance.Lifecycle.PER_CLASS)
        @TestMethodOrder(OrderAnnotation.class)
        class User {

            private String accessToken;

            private String refreshToken;

            private String xAuthToken;

            private String username;

            private String code;

            private String state;

            @BeforeAll
            void username() {

                username = "jean.dupond@gmail.com";
            }

            @Test
            @Order(0)
            void credentials() throws ParseException {

                // Given client credentials

                Map<String, String> params = Map.of("grant_type", "client_credentials", "scope", "ROLE_APP");

                // When perform get access token

                Response response = requestSpecification
                        .header("Authorization", "Basic " + Base64.encodeBase64String("test:secret_test".getBytes()))
                        .formParams(params)
                        .post("/oauth/token");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                        () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

                accessToken = response.jsonPath().getString("access_token");

                // And check token

                var payload = SignedJWT.parse(accessToken).getJWTClaimsSet();
                assertAll(
                        () -> assertThat(payload.getClaim("client_id")).isEqualTo("test"),
                        () -> assertThat(payload.getStringListClaim("scope")).contains("ROLE_APP"));

            }

            @Test
            @Order(1)
            void login() {

                // Given mock login resource

                LoginEntity account = new LoginEntity();
                account.setUsername(username);
                account.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));

                when(resource.get(username)).thenReturn(Optional.of(account));

                // When perform login

                Response response = requestSpecification.header("Authorization", "Bearer " + accessToken)
                        .formParams("username", username, "password", "123")
                        .post("/login");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value()),
                        () -> assertThat(response.getHeader("X-Auth-Token")).isNotNull(),
                        () -> assertThat(response.getCookies()).isEmpty());

                xAuthToken = response.getHeader("X-Auth-Token");

            }

            @Test
            @Order(2)
            void authorize() {

                // When perform authorize

                String authorizeUrl = "http://localhost:" + localPort
                        + "/oauth/authorize?response_type=code&client_id=test_user&scope=account:read&state=123";
                Response response = requestSpecification.when().redirects().follow(false).header("X-Auth-Token", xAuthToken).get(authorizeUrl);

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value()),
                        () -> assertThat(response.getHeader(HttpHeaders.LOCATION)).isNotNull());

                String location = response.getHeader(HttpHeaders.LOCATION);

                // And check location

                Matcher locationMatcher = LOCATION.matcher(location);
                assertThat(locationMatcher.lookingAt()).isTrue();

                code = locationMatcher.group(1);
                state = locationMatcher.group(3);

                // And check state

                assertThat(state).isEqualTo("123");

            }

            @Test
            @Order(3)
            void token() throws ParseException {

                // When perform get access token

                Map<String, String> params = Map.of(
                        "grant_type", "authorization_code",
                        "code", code,
                        "client_id", "test_user",
                        "redirect_uri", "/ws/test");

                Response response = requestSpecification
                        .header("Authorization", "Basic " + Base64.encodeBase64String("test_user:secret_test_user".getBytes()))
                        .formParams(params)
                        .post("/oauth/token");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                        () -> assertThat(response.jsonPath().getString("access_token")).isNotNull(),
                        () -> assertThat(response.jsonPath().getString("refresh_token")).isNotNull());

                accessToken = response.jsonPath().getString("access_token");
                refreshToken = response.jsonPath().getString("refresh_token");

                // And check token

                var payload = SignedJWT.parse(accessToken).getJWTClaimsSet();
                assertAll(
                        () -> assertThat(payload.getJWTID()).isNotNull(),
                        () -> assertThat(payload.getClaim("client_id")).isEqualTo("test_user"),
                        () -> assertThat(payload.getSubject()).isEqualTo(username),
                        () -> assertThat(payload.getStringListClaim("authorities")).contains("ROLE_ACCOUNT"),
                        () -> assertThat(payload.getStringListClaim("scope")).contains("account:read"));
            }

            @Test
            @Order(4)
            void refreshToken() throws ParseException {

                // When perform refresh token

                Map<String, String> params = Map.of(
                        "grant_type", "refresh_token",
                        "client_id", "test_user",
                        "refresh_token", refreshToken);

                Response response = requestSpecification
                        .header("Authorization", "Basic " + Base64.encodeBase64String("test_user:secret_test_user".getBytes()))
                        .formParams(params)
                        .post("/oauth/token");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                        () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

                accessToken = response.jsonPath().getString("access_token");

                // And check token

                var payload = SignedJWT.parse(accessToken).getJWTClaimsSet();
                assertAll(
                        () -> assertThat(payload.getJWTID()).isNotNull(),
                        () -> assertThat(payload.getClaim("client_id")).isEqualTo("test_user"),
                        () -> assertThat(payload.getSubject()).isEqualTo(username),
                        () -> assertThat(payload.getStringListClaim("authorities")).contains("ROLE_ACCOUNT"),
                        () -> assertThat(payload.getStringListClaim("scope")).contains("account:read"));
            }

            @Test
            @Order(4)
            void tokenFailure() {

                // When perform get access token

                Map<String, String> params = Map.of(
                        "grant_type", "authorization_code",
                        "code", code,
                        "client_id", "test_user",
                        "redirect_uri", "/ws/test");

                Response response = requestSpecification
                        .header("Authorization", "Basic " + Base64.encodeBase64String("test_user:secret_test_user".getBytes()))
                        .formParams(params)
                        .post("/oauth/token");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value()),
                        () -> assertThat(response.jsonPath().getString("error")).isEqualTo("invalid_grant"));

            }

            @Test
            @Order(5)
            void checkToken() throws ParseException {

                // When perform check token

                Map<String, String> params = Map.of("token", accessToken);

                Response response = requestSpecification
                        .header("Authorization", "Basic " + Base64.encodeBase64String("resource:secret_resource".getBytes()))
                        .formParams(params)
                        .post("/oauth/check_token");

                // Then check response

                assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

                // And check payload

                var payload = JWTClaimsSet.parse(response.getBody().print());

                assertAll(
                        () -> assertThat(payload.getJWTID()).isNotNull(),
                        () -> assertThat(payload.getSubject()).isEqualTo(username),
                        () -> assertThat(payload.getStringListClaim("authorities")).contains("ROLE_ACCOUNT"),
                        () -> assertThat(payload.getStringClaim("scope")).isEqualTo("account:read"));

            }

        }

        @Nested
        @TestInstance(TestInstance.Lifecycle.PER_CLASS)
        @TestMethodOrder(OrderAnnotation.class)
        class Back {

            private String accessToken;

            private String refreshToken;

            private String xAuthToken;

            private String username;

            private String code;

            private String state;

            @BeforeAll
            void username() {

                username = "admin";
            }

            @Test
            @Order(0)
            void credentials() throws ParseException {

                // Given client credentials

                Map<String, String> params = Map.of("grant_type", "client_credentials", "scope", "ROLE_BACK");

                // When perform get access token

                Response response = requestSpecification
                        .header("Authorization", "Basic " + Base64.encodeBase64String("test:secret_test".getBytes()))
                        .formParams(params)
                        .post("/oauth/token");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                        () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

                accessToken = response.jsonPath().getString("access_token");

                // And check token

                var payload = SignedJWT.parse(accessToken).getJWTClaimsSet();
                assertAll(
                        () -> assertThat(payload.getClaim("client_id")).isEqualTo("test"),
                        () -> assertThat(payload.getStringListClaim("scope")).contains("ROLE_BACK"));

            }

            @Test
            @Order(1)
            void login() {

                // When perform login

                Response response = requestSpecification.header("Authorization", "Bearer " + accessToken)
                        .formParams("username", username, "password", "admin123")
                        .post("/login");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value()),
                        () -> assertThat(response.getHeader("X-Auth-Token")).isNotNull(),
                        () -> assertThat(response.getCookies()).isEmpty());

                xAuthToken = response.getHeader("X-Auth-Token");

            }

            @Test
            @Order(2)
            void authorize() {

                // When perform authorize

                String authorizeUrl = "http://localhost:" + localPort
                        + "/oauth/authorize?response_type=code&client_id=test_back&scope=stock:read&state=123";
                Response response = requestSpecification.when().redirects().follow(false).header("X-Auth-Token", xAuthToken).get(authorizeUrl);

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value()),
                        () -> assertThat(response.getHeader(HttpHeaders.LOCATION)).isNotNull());

                String location = response.getHeader(HttpHeaders.LOCATION);

                // And check location

                Matcher locationMatcher = LOCATION.matcher(location);
                assertThat(locationMatcher.lookingAt()).isTrue();

                code = locationMatcher.group(1);
                state = locationMatcher.group(3);

                // And check state

                assertThat(state).isEqualTo("123");

            }

            @Test
            @Order(3)
            void token() throws ParseException {

                // When perform get access token

                Map<String, String> params = Map.of(
                        "grant_type", "authorization_code",
                        "code", code,
                        "client_id", "test_back",
                        "redirect_uri", "/ws/test");

                Response response = requestSpecification
                        .header("Authorization", "Basic " + Base64.encodeBase64String("test_back:secret_test_back".getBytes()))
                        .formParams(params)
                        .post("/oauth/token");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                        () -> assertThat(response.jsonPath().getString("access_token")).isNotNull(),
                        () -> assertThat(response.jsonPath().getString("refresh_token")).isNotNull());

                accessToken = response.jsonPath().getString("access_token");
                refreshToken = response.jsonPath().getString("refresh_token");

                // And check token

                var payload = SignedJWT.parse(accessToken).getJWTClaimsSet();
                assertAll(
                        () -> assertThat(payload.getJWTID()).isNotNull(),
                        () -> assertThat(payload.getClaim("client_id")).isEqualTo("test_back"),
                        () -> assertThat(payload.getSubject()).isEqualTo(username),
                        () -> assertThat(payload.getStringListClaim("authorities")).contains("ROLE_BACK"),
                        () -> assertThat(payload.getStringListClaim("scope")).contains("stock:read"));
            }

            @Test
            @Order(4)
            void refreshToken() throws ParseException {

                // When perform refresh token

                Map<String, String> params = Map.of(
                        "grant_type", "refresh_token",
                        "client_id", "test_back",
                        "refresh_token", refreshToken);

                Response response = requestSpecification
                        .header("Authorization", "Basic " + Base64.encodeBase64String("test_back:secret_test_back".getBytes()))
                        .formParams(params)
                        .post("/oauth/token");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                        () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

                accessToken = response.jsonPath().getString("access_token");

                // And check token

                var payload = SignedJWT.parse(accessToken).getJWTClaimsSet();
                assertAll(
                        () -> assertThat(payload.getJWTID()).isNotNull(),
                        () -> assertThat(payload.getClaim("client_id")).isEqualTo("test_back"),
                        () -> assertThat(payload.getSubject()).isEqualTo(username),
                        () -> assertThat(payload.getStringListClaim("authorities")).contains("ROLE_BACK"),
                        () -> assertThat(payload.getStringListClaim("scope")).contains("stock:read"));
            }

            @Test
            @Order(4)
            void tokenFailure() {

                // When perform get access token

                Map<String, String> params = Map.of(
                        "grant_type", "authorization_code",
                        "code", code,
                        "client_id", "test_back",
                        "redirect_uri", "/ws/test");

                Response response = requestSpecification
                        .header("Authorization", "Basic " + Base64.encodeBase64String("test_back:secret_test_back".getBytes()))
                        .formParams(params)
                        .post("/oauth/token");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value()),
                        () -> assertThat(response.jsonPath().getString("error")).isEqualTo("invalid_grant"));

            }

            @Test
            @Order(5)
            void checkToken() throws ParseException {

                // When perform check token

                Map<String, String> params = Map.of("token", accessToken);

                Response response = requestSpecification
                        .header("Authorization", "Basic " + Base64.encodeBase64String("resource:secret_resource".getBytes()))
                        .formParams(params)
                        .post("/oauth/check_token");

                // Then check response

                assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

                // And check payload

                var payload = JWTClaimsSet.parse(response.getBody().print());

                assertAll(
                        () -> assertThat(payload.getJWTID()).isNotNull(),
                        () -> assertThat(payload.getSubject()).isEqualTo(username),
                        () -> assertThat(payload.getStringListClaim("authorities")).contains("ROLE_BACK"),
                        () -> assertThat(payload.getStringClaim("scope")).isEqualTo("stock:read"));

            }

        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    @TestMethodOrder(OrderAnnotation.class)
    class AuthorizationByPKCE {

        private String accessToken;

        private String xAuthToken;

        private String username;

        private String code;

        private String state;

        private String codeVerifier;

        @BeforeAll
        void username() {

            username = "jean.dupond@gmail.com";
        }

        @Test
        @Order(0)
        void credentials() throws ParseException {

            // Given client credentials

            Map<String, String> params = Map.of("grant_type", "client_credentials", "scope", "ROLE_APP");

            // When perform get access token

            Response response = requestSpecification
                    .header("Authorization", "Basic " + Base64.encodeBase64String("test:secret_test".getBytes()))
                    .formParams(params)
                    .post("/oauth/token");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                    () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

            accessToken = response.jsonPath().getString("access_token");

            // And check token

            var payload = SignedJWT.parse(accessToken).getJWTClaimsSet();
            assertAll(
                    () -> assertThat(payload.getClaim("client_id")).isEqualTo("test"),
                    () -> assertThat(payload.getStringListClaim("scope")).contains("ROLE_APP"));

        }

        @Test
        @Order(1)
        void login() {

            // Given mock login resource

            LoginEntity account = new LoginEntity();
            account.setUsername(username);
            account.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));

            when(resource.get(username)).thenReturn(Optional.of(account));

            // When perform login

            Response response = requestSpecification.header("Authorization", "Bearer " + accessToken)
                    .formParams("username", username, "password", "123")
                    .post("/login");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value()),
                    () -> assertThat(response.getHeader("X-Auth-Token")).isNotNull(),
                    () -> assertThat(response.getCookies()).isEmpty());

            xAuthToken = response.getHeader("X-Auth-Token");

        }

        @Test
        @Order(2)
        void authorize() {

            // setup code verifier
            codeVerifier = UUID.randomUUID().toString();

            var digest = DigestUtils.sha256(codeVerifier);
            var codeChallenge = Base64.encodeBase64URLSafeString(digest);

            // When perform authorize

            String authorizeUrl = "http://localhost:" + localPort
                    + "/oauth/authorize?response_type=code&client_id=test_user_pkce&scope=account:read&state=123&code_challenge="
                    + codeChallenge
                    + "&code_challenge_method=S256";
            Response response = requestSpecification.when().redirects().follow(false).header("X-Auth-Token", xAuthToken).get(authorizeUrl);

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value()),
                    () -> assertThat(response.getHeader(HttpHeaders.LOCATION)).isNotNull());

            String location = response.getHeader(HttpHeaders.LOCATION);

            // And check location

            Matcher locationMatcher = LOCATION.matcher(location);
            assertThat(locationMatcher.lookingAt()).isTrue();

            code = locationMatcher.group(1);
            state = locationMatcher.group(3);

            // And check state

            assertThat(state).isEqualTo("123");

        }

        @Test
        @Order(3)
        void token() throws ParseException {

            // When perform get access token

            Map<String, String> params = Map.of(
                    "grant_type", "authorization_code",
                    "code", code,
                    "code_verifier", codeVerifier,
                    "client_id", "test_user_pkce",
                    "redirect_uri", "/ws/test");

            Response response = requestSpecification
                    .formParams(params)
                    .post("/oauth/token");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                    () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

            accessToken = response.jsonPath().getString("access_token");

            // And check token

            var payload = SignedJWT.parse(accessToken).getJWTClaimsSet();
            assertAll(
                    () -> assertThat(payload.getJWTID()).isNotNull(),
                    () -> assertThat(payload.getClaim("client_id")).isEqualTo("test_user_pkce"),
                    () -> assertThat(payload.getSubject()).isEqualTo(username),
                    () -> assertThat(payload.getStringListClaim("authorities")).contains("ROLE_ACCOUNT"),
                    () -> assertThat(payload.getStringListClaim("scope")).contains("account:read"));
        }

        @Test
        @Order(4)
        void checkToken() throws ParseException {

            // When perform check token

            Map<String, String> params = Map.of("token", accessToken);

            Response response = requestSpecification
                    .header("Authorization", "Basic " + Base64.encodeBase64String("resource:secret_resource".getBytes()))
                    .formParams(params)
                    .post("/oauth/check_token");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

            // And check payload

            var payload = JWTClaimsSet.parse(response.getBody().print());

            assertAll(
                    () -> assertThat(payload.getJWTID()).isNotNull(),
                    () -> assertThat(payload.getSubject()).isEqualTo(username),
                    () -> assertThat(payload.getStringListClaim("authorities")).contains("ROLE_ACCOUNT"),
                    () -> assertThat(payload.getStringClaim("scope")).isEqualTo("account:read"));

        }
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    @TestMethodOrder(OrderAnnotation.class)
    class AuthorizationByCredentials {

        private String accessToken;

        @Test
        @Order(0)
        void credentials() throws ParseException {

            // Given client credentials

            Map<String, String> params = Map.of("grant_type", "client_credentials", "scope", "account:create");

            // When perform get access token

            Response response = requestSpecification
                    .header("Authorization", "Basic " + Base64.encodeBase64String("test:secret_test".getBytes()))
                    .formParams(params)
                    .post("/oauth/token");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                    () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

            accessToken = response.jsonPath().getString("access_token");

            // And check token

            var payload = SignedJWT.parse(accessToken).getJWTClaimsSet();
            assertAll(
                    () -> assertThat(payload.getClaim("client_id")).isEqualTo("test"),
                    () -> assertThat(payload.getStringListClaim("scope")).contains("account:create"));

        }

        Stream<Arguments> credentialsFailure() {

            return Stream.of(
                    // bad password
                    Arguments.of("test", UUID.randomUUID().toString()),
                    // bad login
                    Arguments.of(UUID.randomUUID().toString(), "secret"));
        }

        @ParameterizedTest
        @MethodSource
        void credentialsFailure(String login, String password) {

            // Given client credentials

            Map<String, String> params = Map.of("grant_type", "client_credentials");

            // When perform get access token

            Response response = requestSpecification
                    .header("Authorization", "Basic " + Base64.encodeBase64String((login + ":" + password).getBytes()))
                    .formParams(params)
                    .post("/oauth/token");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value()),
                    () -> assertThat(response.jsonPath().getString("error")).isEqualTo("invalid_client"));

        }

        @Order(1)
        @Test
        void checkToken() throws ParseException {

            // When perform check token

            Map<String, String> params = Map.of("token", accessToken);

            Response response = requestSpecification
                    .header("Authorization", "Basic " + Base64.encodeBase64String("resource:secret_resource".getBytes()))
                    .formParams(params)
                    .post("/oauth/check_token");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

            // And check payload

            var payload = JWTClaimsSet.parse(response.getBody().print());

            assertAll(
                    () -> assertThat(payload.getBooleanClaim("active")).isTrue(),
                    () -> assertThat(payload.getClaim("client_id")).isEqualTo("test"),
                    () -> assertThat(payload.getClaim("scope")).isEqualTo("account:create"));

        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    @TestMethodOrder(OrderAnnotation.class)
    class Login {

        private String username;

        @BeforeAll
        void username() {

            username = "test";
        }

        @Test
        @DisplayName("fails because token is in black list")
        void failsBecauseTokenIsInBlackList() throws JOSEException {

            // Given token

            String deprecatedTokenId = UUID.randomUUID().toString();
            client.getMap(AuthorizationJwtConfiguration.TOKEN_BLACK_LIST).put(deprecatedTokenId,
                    Date.from(Instant.now()));

            var payload = new JWTClaimsSet.Builder()
                    .audience("app1")
                    .claim("client_id", "test")
                    .claim("scope", new String[] { "account:create", "ROLE_APP" })
                    .jwtID(deprecatedTokenId)
                    .build();

            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(algorithm);

            // When perform login

            Response response = requestSpecification.header("Authorization", "Bearer " + accessToken.serialize())
                    .formParams("username", username, "password", "123")
                    .post("/login");

            // Then check status

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value()),
                    () -> assertThat(response.getHeader("WWW-Authenticate")).contains(deprecatedTokenId + " has been excluded"));

            // And verify resource

            verify(resource, never()).get(any());

        }

        @Test
        @DisplayName("fails because public key doesn't check signature")
        void failsBecausePublicKeyDoesntCheckSignature() throws JOSEException {

            // Given token

            var payload = new JWTClaimsSet.Builder()
                    .audience("app1")
                    .claim("client_id", "test")
                    .claim("scope", new String[] { "account:create", "ROLE_APP" })
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(new RSASSASigner(OTHER_RSA_KEY));

            // When perform login

            Response response = requestSpecification.header("Authorization", "Bearer " + accessToken.serialize())
                    .formParams("username", username, "password", "123")
                    .post("/login");

            // Then check status

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value()),
                    () -> assertThat(response.getHeader("WWW-Authenticate")).contains("Invalid signature"));

            // And verify resource

            verify(resource, never()).get(any());

        }

        @Test
        @DisplayName("fails because public token is deprecated")
        void failsBecauseTokenIsDeprecated() throws JOSEException {

            // Given token

            var payload = new JWTClaimsSet.Builder()
                    .audience("app1")
                    .claim("client_id", "test")
                    .claim("scope", new String[] { "account:create", "ROLE_APP" })
                    .expirationTime(Date.from(Instant.now().minusSeconds(1)))
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(algorithm);

            // When perform login

            Response response = requestSpecification.header("Authorization", "Bearer " + accessToken.serialize())
                    .formParams("username", username, "password", "123")
                    .post("/login");

            // Then check status

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value()),
                    () -> assertThat(response.getHeader("WWW-Authenticate")).contains("Jwt expired at "));

            // And verify resource

            verify(resource, never()).get(any());

        }

        @Test
        @DisplayName("fails because public token is missing")
        void failsBecauseTokenIsMissing() {

            // When perform get

            Response response = requestSpecification
                    .formParams("username", username, "password", "123")
                    .post("/login");

            // Then check status

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        }

        @Test
        @DisplayName("fails because authorities no match")
        void failureBecauseAuthoritiesNoMatch() throws JOSEException {

            // Given token

            var payload = new JWTClaimsSet.Builder()
                    .audience("app1")
                    .claim("client_id", "test")
                    .claim("scope", new String[] { "account:create", "OTHER" })
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(algorithm);

            // When perform login

            Response response = requestSpecification.header("Authorization", "Bearer " + accessToken.serialize())
                    .formParams("username", username, "password", "123")
                    .post("/login");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());

            // And verify resource

            verify(resource, never()).get(any());

        }

        @Test
        @DisplayName("fails because back login is wrong")
        void failureBecauseBackLoginIsWrong() throws JOSEException {

            // Given token

            var payload = new JWTClaimsSet.Builder()
                    .audience("app1")
                    .claim("client_id", "test")
                    .claim("scope", new String[] { "account:create", "ROLE_BACK" })
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(algorithm);

            // When perform login

            Response response = requestSpecification.header("Authorization", "Bearer " + accessToken.serialize())
                    .formParams("username", "other", "password", "admin123")
                    .post("/login");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());

        }

        @Nested
        @TestInstance(TestInstance.Lifecycle.PER_CLASS)
        class User {

            private String username;

            @BeforeAll
            void username() {

                username = "jean.dupond@gmail.com";
            }

            @Test
            @DisplayName("fails because user login is wrong")
            void failureBecauseUserLoginIsWrong() throws JOSEException {

                // Given token

                var payload = new JWTClaimsSet.Builder()
                        .audience("app1")
                        .claim("client_id", "test")
                        .claim("scope", new String[] { "account:create", "ROLE_APP" })
                        .jwtID(UUID.randomUUID().toString())
                        .build();

                var accessToken = new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                        payload);
                accessToken.sign(algorithm);

                // And mock login resource

                when(resource.get(username)).thenReturn(Optional.empty());

                // When perform login

                Response response = requestSpecification.header("Authorization", "Bearer " + accessToken.serialize())
                        .formParams("username", username, "password", "123")
                        .post("/login");

                // Then check response

                assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());

            }

            @Test
            void success() throws JOSEException {

                // Given token

                var payload = new JWTClaimsSet.Builder()
                        .audience("app1")
                        .claim("client_id", "test")
                        .claim("scope", new String[] { "account:create", "ROLE_APP" })
                        .jwtID(UUID.randomUUID().toString())
                        .build();

                var accessToken = new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                        payload);
                accessToken.sign(algorithm);

                // Given mock login resource

                LoginEntity account = new LoginEntity();
                account.setUsername(username);
                account.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));

                when(resource.get(username)).thenReturn(Optional.of(account));

                // When perform login

                Response response = requestSpecification.header("Authorization", "Bearer " + accessToken.serialize())
                        .formParams("username", username, "password", "123")
                        .post("/login");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value()),
                        () -> assertThat(response.getHeader("X-Auth-Token")).isNotNull(),
                        () -> assertThat(response.getCookies()).isEmpty());

            }
        }

        @Nested
        @TestInstance(TestInstance.Lifecycle.PER_CLASS)
        class Back {

            private String username;

            @BeforeAll
            void username() {

                username = "admin";
            }

            @Test
            @DisplayName("fails because user login is wrong")
            void failureBecauseUserLoginIsWrong() throws JOSEException {

                // Given token

                var payload = new JWTClaimsSet.Builder()
                        .audience("app1")
                        .claim("client_id", "test")
                        .claim("scope", new String[] { "account:create", "ROLE_BACK" })
                        .jwtID(UUID.randomUUID().toString())
                        .build();

                var accessToken = new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                        payload);
                accessToken.sign(algorithm);

                // And mock login resource

                when(resource.get(username)).thenReturn(Optional.empty());

                // When perform login

                Response response = requestSpecification.header("Authorization", "Bearer " + accessToken.serialize())
                        .formParams("username", "other", "password", "admin123")
                        .post("/login");

                // Then check response

                assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());

            }

            @Test
            void success() throws JOSEException {

                // Given token

                var payload = new JWTClaimsSet.Builder()
                        .audience("app1")
                        .claim("client_id", "test")
                        .claim("scope", new String[] { "account:create", "ROLE_BACK" })
                        .jwtID(UUID.randomUUID().toString())
                        .build();

                var accessToken = new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                        payload);
                accessToken.sign(algorithm);

                // Given mock login resource

                LoginEntity account = new LoginEntity();
                account.setUsername(username);
                account.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));

                when(resource.get(username)).thenReturn(Optional.of(account));

                // When perform login

                Response response = requestSpecification.header("Authorization", "Bearer " + accessToken.serialize())
                        .formParams("username", username, "password", "admin123")
                        .post("/login");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value()),
                        () -> assertThat(response.getHeader("X-Auth-Token")).isNotNull(),
                        () -> assertThat(response.getCookies()).isEmpty());

            }

        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class Instrospection {

        private String username;

        @BeforeAll
        void username() {

            username = "jean.dupond@gmail.com";
        }

        @Test
        @DisplayName("fails because token is in black list")
        void failsBecauseTokenIsInBlackList() throws JOSEException {

            // Given token

            String deprecatedTokenId = UUID.randomUUID().toString();
            client.getMap(AuthorizationJwtConfiguration.TOKEN_BLACK_LIST).put(deprecatedTokenId,
                    Date.from(Instant.now()));

            var payload = new JWTClaimsSet.Builder()
                    .claim("client_id", "test")
                    .subject(username)
                    .claim("scope", new String[] { "account:read" })
                    .jwtID(deprecatedTokenId)
                    .build();

            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(algorithm);

            // When perform check token

            Map<String, String> params = Map.of("token", accessToken.serialize());

            Response response = requestSpecification
                    .header("Authorization", "Basic " + Base64.encodeBase64String("resource:secret_resource".getBytes()))
                    .formParams(params)
                    .post("/oauth/check_token");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                    () -> assertThat(response.jsonPath().getBoolean("active")).isFalse());
        }

        @Test
        @DisplayName("fails because public key doesn't check signature")
        void failsBecausePublicKeyDoesntCheckSignature() throws JOSEException {

            // Given token

            var payload = new JWTClaimsSet.Builder()
                    .claim("client_id", "test")
                    .subject(username)
                    .claim("scope", new String[] { "account:read" })
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(new RSASSASigner(OTHER_RSA_KEY));

            // When perform check token

            Map<String, String> params = Map.of("token", accessToken.serialize());

            Response response = requestSpecification
                    .header("Authorization", "Basic " + Base64.encodeBase64String("resource:secret_resource".getBytes()))
                    .formParams(params)
                    .post("/oauth/check_token");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                    () -> assertThat(response.jsonPath().getBoolean("active")).isFalse());
        }

        @Test
        @DisplayName("fails because public token is deprecated")
        void failsBecauseTokenIsDeprecated() throws JOSEException {

            // Given token

            var payload = new JWTClaimsSet.Builder()
                    .claim("client_id", "test")
                    .subject(username)
                    .claim("scope", new String[] { "account:read" })
                    .expirationTime(Date.from(Instant.now().minusSeconds(1)))
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(algorithm);

            // When perform check token

            Map<String, String> params = Map.of("token", accessToken.serialize());

            Response response = requestSpecification
                    .header("Authorization", "Basic " + Base64.encodeBase64String("resource:secret_resource".getBytes()))
                    .formParams(params)
                    .post("/oauth/check_token");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                    () -> assertThat(response.jsonPath().getBoolean("active")).isFalse());
        }

        @Test
        void success() throws JOSEException, ParseException {

            // Given token

            var payload = new JWTClaimsSet.Builder()
                    .claim("client_id", "test")
                    .subject(username)
                    .claim("scope", new String[] { "account:read" })
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(algorithm);

            // When perform check token

            Map<String, String> params = Map.of("token", accessToken.serialize());

            Response response = requestSpecification
                    .header("Authorization", "Basic " + Base64.encodeBase64String("resource:secret_resource".getBytes()))
                    .formParams(params)
                    .post("/oauth/check_token");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

            // And check payload

            var responsePayload = JWTClaimsSet.parse(response.getBody().print());

            assertAll(
                    () -> assertThat(responsePayload.getJWTID()).isNotNull(),
                    () -> assertThat(responsePayload.getBooleanClaim("active")).isTrue(),
                    () -> assertThat(responsePayload.getSubject()).isEqualTo(username),
                    () -> assertThat(responsePayload.getStringClaim("scope")).isEqualTo("account:read"));

        }

    }

    @Nested
    class Revocation {

        @Test
        void revokeJwtToken() throws JOSEException {

            // setup token

            var payload = new JWTClaimsSet.Builder()
                    .claim("client_id", "test_user")
                    .subject("jean.dupond@gmail.com")
                    .claim("scope", new String[] { "account:read" })
                    .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(algorithm);
            Map<String, String> params = Map.of("token", accessToken.serialize());

            // When perform revoke token

            Response response = requestSpecification
                    .header("Authorization", "Basic " + Base64.encodeBase64String("test_user:secret_test_user".getBytes()))
                    .formParams(params)
                    .post("/oauth/revoke_token");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

            // And check token

            Response checkResponse = RestAssured.given().filters(new LoggingFilter(LOG)).port(localPort)
                    .header("Authorization", "Basic " + Base64.encodeBase64String("resource:secret_resource".getBytes()))
                    .formParams(params)
                    .post("/oauth/check_token");

            assertAll(
                    () -> assertThat(checkResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                    () -> assertThat(checkResponse.jsonPath().getBoolean("active")).isFalse());

        }

        @Test
        void revokeDeprecatedToken() throws JOSEException {

            // setup token

            var payload = new JWTClaimsSet.Builder()
                    .claim("client_id", "test_user")
                    .subject("jean.dupond@gmail.com")
                    .claim("scope", new String[] { "account:read" })
                    .expirationTime(Date.from(Instant.now().minusSeconds(10)))
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(algorithm);
            Map<String, String> params = Map.of("token", accessToken.serialize());

            // When perform revoke token

            Response response = requestSpecification
                    .header("Authorization", "Basic " + Base64.encodeBase64String("test_user:secret_test_user".getBytes()))
                    .formParams(params)
                    .post("/oauth/revoke_token");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

            // And check token

            Response checkResponse = RestAssured.given().filters(new LoggingFilter(LOG)).port(localPort)
                    .header("Authorization", "Basic " + Base64.encodeBase64String("resource:secret_resource".getBytes()))
                    .formParams(params)
                    .post("/oauth/check_token");

            assertAll(
                    () -> assertThat(checkResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                    () -> assertThat(checkResponse.jsonPath().getBoolean("active")).isFalse());

        }

        static Stream<Arguments> revokeJwtTokenFailure() {

            var payloadWithoutId = new JWTClaimsSet.Builder()
                    .claim("client_id", "test_user")
                    .subject("jean.dupond@gmail.com")
                    .claim("scope", new String[] { "account:read" })
                    .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                    .build();

            var payloadWithoutExp = new JWTClaimsSet.Builder()
                    .claim("client_id", "test_user")
                    .subject("jean.dupond@gmail.com")
                    .claim("scope", new String[] { "account:read" })
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            return Stream.of(
                    Arguments.of(payloadWithoutId),
                    Arguments.of(payloadWithoutExp));
        }

        @ParameterizedTest
        @MethodSource
        void revokeJwtTokenFailure(JWTClaimsSet payload) throws JOSEException {

            // setup token
            var accessToken = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    payload);
            accessToken.sign(algorithm);
            Map<String, String> params = Map.of("token", accessToken.serialize());

            // When perform revoke token

            Response response = requestSpecification
                    .header("Authorization", "Basic " + Base64.encodeBase64String("test_user:secret_test_user"
                            .getBytes()))
                    .formParams(params)
                    .post("/oauth/revoke_token");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());

        }

    }
}
