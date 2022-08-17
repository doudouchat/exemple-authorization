package com.exemple.authorization.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mindrot.jbcrypt.BCrypt;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.util.Assert;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.JWTPartsParser;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.jwt.interfaces.Payload;
import com.exemple.authorization.common.LoggingFilter;
import com.exemple.authorization.core.client.AuthorizationClientBuilder;
import com.exemple.authorization.resource.login.LoginResource;
import com.exemple.authorization.resource.login.model.LoginEntity;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(classes = { AuthorizationTestConfiguration.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Slf4j
class AuthorizationServerTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private AuthorizationClientBuilder authorizationClientBuilder;

    @Autowired
    private Algorithm algorithm;

    @Autowired
    private LoginResource resource;

    private RequestSpecification requestSpecification;

    private static final Pattern LOCATION;

    private static final Pattern RSA_PUBLIC_KEY;

    static {

        LOCATION = Pattern.compile(".*code=(\\w*)(&state=)?(.*)?", Pattern.DOTALL);

        RSA_PUBLIC_KEY = Pattern.compile("-----BEGIN PUBLIC KEY-----(.*)-----END PUBLIC KEY-----", Pattern.DOTALL);
    }

    @BeforeAll
    private void init() throws Exception {

        String password = "{bcrypt}" + BCrypt.hashpw("secret", BCrypt.gensalt());

        authorizationClientBuilder
                .withClient("test").secret(password).authorizedGrantTypes("client_credentials").redirectUris("xxx").scopes("account:create")
                .autoApprove("account:create").authorities("ROLE_APP").resourceIds("app1").additionalInformation("keyspace=test")
                .and()
                .withClient("test_user").secret(password).authorizedGrantTypes("password", "authorization_code", "refresh_token")
                .redirectUris("/ws/test").scopes("account:read", "account:update").autoApprove("account:read", "account:update")
                .authorities("ROLE_APP").resourceIds("app1").additionalInformation("keyspace=test")
                .and()
                .withClient("back_user").secret(password).authorizedGrantTypes("password").scopes("stock:read", "stock:update")
                .autoApprove("stock:read", "stock:update").authorities("ROLE_BACK").resourceIds("app1").additionalInformation("keyspace=test")
                .and()
                .withClient("mobile").authorizedGrantTypes("implicit").redirectUris("/ws/test").scopes("account:read", "account:update")
                .autoApprove("account:read", "account:update").authorities("ROLE_APP").resourceIds("app1").additionalInformation("keyspace=test")
                .and()
                .withClient("resource").secret(password).authorizedGrantTypes("client_credentials").authorities("ROLE_TRUSTED_CLIENT")
                .and().build();

    }

    @BeforeEach
    private void before() {

        Mockito.reset(resource);

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG));

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    @TestMethodOrder(OrderAnnotation.class)
    class AuthorizationByCode {

        private String accessToken;

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
        void credentials() {

            // Given client credentials

            Map<String, String> params = new HashMap<>();
            params.put("grant_type", "client_credentials");

            // When perform get access token

            Response response = requestSpecification.auth().basic("test", "secret").formParams(params)
                    .post(restTemplate.getRootUri() + "/oauth/token");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                    () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

            accessToken = response.jsonPath().getString("access_token");

        }

        @Test
        @Order(1)
        void login() {

            // Given mock login resource

            LoginEntity account = new LoginEntity();
            account.setUsername(username);
            account.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));

            Mockito.when(resource.get(username)).thenReturn(Optional.of(account));

            // When perform login

            Response response = requestSpecification.header("Authorization", "Bearer " + accessToken)
                    .formParams("username", username, "password", "123")
                    .post(restTemplate.getRootUri() + "/login");

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

            String authorizeUrl = restTemplate.getRootUri() + "/oauth/authorize?response_type=code&client_id=test_user&scope=account:read&state=123";
            Response response = requestSpecification.when().redirects().follow(false).header("X-Auth-Token", xAuthToken).get(authorizeUrl);

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SEE_OTHER.value()),
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
        void token() {

            // When perform get access token

            Map<String, String> params = new HashMap<>();
            params.put("grant_type", "authorization_code");
            params.put("code", code);
            params.put("client_id", "test_user");
            params.put("redirect_uri", "/ws/test");

            Response response = requestSpecification.auth().basic("test_user", "secret").formParams(params)
                    .post(restTemplate.getRootUri() + "/oauth/token");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                    () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

            accessToken = response.jsonPath().getString("access_token");

            // And check payload

            JWTPartsParser parser = new JWTParser();
            Payload payload = parser.parsePayload(response.getBody().print());

            assertAll(
                    () -> assertThat(payload.getSubject()).isEqualTo(username),
                    () -> assertThat(payload.getClaim("authorities").asArray(String.class)).contains("ROLE_ACCOUNT"));

        }

        @Test
        @Order(4)
        void tokenFailure() {

            // When perform get access token

            Map<String, String> params = new HashMap<>();
            params.put("grant_type", "authorization_code");
            params.put("code", code);
            params.put("client_id", "test_user");
            params.put("redirect_uri", "xxx");

            Response response = requestSpecification.auth().basic("test_user", "secret").formParams(params)
                    .post(restTemplate.getRootUri() + "/oauth/token");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());

        }

        @Test
        @Order(5)
        void checkToken() {

            // When perform check token

            Map<String, String> params = new HashMap<>();
            params.put("token", accessToken);

            Response response = requestSpecification.auth().basic("resource", "secret").formParams(params)
                    .post(restTemplate.getRootUri() + "/oauth/check_token");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

            // And check payload

            JWTPartsParser parser = new JWTParser();
            Payload payload = parser.parsePayload(response.getBody().print());

            assertAll(
                    () -> assertThat(payload.getClaim("user_name").asString()).isEqualTo(username),
                    () -> assertThat(payload.getSubject()).isEqualTo(username),
                    () -> assertThat(payload.getClaim("aud").asArray(String.class)).contains("app1"),
                    () -> assertThat(payload.getClaim("authorities").asArray(String.class)).contains("ROLE_ACCOUNT"),
                    () -> assertThat(payload.getClaim("scope").asArray(String.class)).contains("account:read"));

        }

        private Stream<Arguments> loginFailure() {

            String accessToken1 = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_ACCOUNT" }).sign(algorithm);
            String accessToken2 = JWT.create().withExpiresAt(new Date(Instant.now().minus(1, ChronoUnit.HOURS).toEpochMilli()))
                    .withArrayClaim("authorities", new String[] { "ROLE_APP" }).sign(algorithm);
            String accessToken3 = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_APP" }).sign(algorithm);
            String accessToken4 = JWT.create().sign(algorithm);

            return Stream.of(
                    // not authorities to access
                    Arguments.of("Authorization", "Bearer " + accessToken1),
                    // token is expired
                    Arguments.of("Authorization", "Bearer " + accessToken2),
                    // not bearer
                    Arguments.of("Authorization", accessToken3),
                    // not token
                    Arguments.of("Header", "Bearer " + accessToken3),
                    // auhorities is empty
                    Arguments.of("Authorization", "Bearer " + accessToken4),
                    // token no recognized
                    Arguments.of("Authorization", "Bearer toto"));
        }

        @ParameterizedTest
        @MethodSource
        void loginFailure(String header, String headerValue) {
            
            // Given mock login resource

            LoginEntity account = new LoginEntity();
            account.setUsername(username);
            account.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));

            Mockito.when(resource.get(username)).thenReturn(Optional.of(account));
            
            // When perform get access token

            Response response = requestSpecification.header(header, headerValue).formParams("username", username, "password", "123")
                    .post(restTemplate.getRootUri() + "/login");
            
            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());

        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    @TestMethodOrder(OrderAnnotation.class)
    class AuthorizationByCredentials {

        private String accessToken;

        @Test
        @Order(0)
        void credentials() {

            // Given client credentials

            Map<String, String> params = new HashMap<>();
            params.put("grant_type", "client_credentials");

            // When perform get access token

            Response response = requestSpecification.auth().basic("test", "secret").formParams(params)
                    .post(restTemplate.getRootUri() + "/oauth/token");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                    () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

            accessToken = response.jsonPath().getString("access_token");

        }

        private Stream<Arguments> credentialsFailure() {

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

            Map<String, String> params = new HashMap<>();
            params.put("grant_type", "client_credentials");

            // When perform get access token

            Response response = requestSpecification.auth().basic(login, password).formParams(params)
                    .post(restTemplate.getRootUri() + "/oauth/token");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());

        }

        @Order(1)
        @Test
        void checkToken() {

            // When perform check token

            Map<String, String> params = new HashMap<>();
            params.put("token", accessToken);

            Response response = requestSpecification.auth().basic("resource", "secret").formParams(params)
                    .post(restTemplate.getRootUri() + "/oauth/check_token");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

            // And check payload

            JWTPartsParser parser = new JWTParser();
            Payload payload = parser.parsePayload(response.getBody().print());

            assertAll(
                    () -> assertThat(payload.getClaim("aud").asArray(String.class)).contains("app1"),
                    () -> assertThat(payload.getClaim("authorities").asArray(String.class)).contains("ROLE_APP"),
                    () -> assertThat(payload.getClaim("scope").asArray(String.class)).contains("account:create"));

        }

        @Order(1)
        @Test
        void checkTokenFailure() {

            // When perform check token

            Map<String, String> params = new HashMap<>();
            params.put("token", accessToken);

            Response response = requestSpecification.auth().basic("test", "secret").formParams(params)
                    .post(restTemplate.getRootUri() + "/oauth/check_token");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());

        }

        @Order(1)
        @Test
        void tokenKey() throws GeneralSecurityException {

            // When perform get token key

            Response response = requestSpecification.auth().basic("resource", "secret").get(restTemplate.getRootUri() + "/oauth/token_key");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                    () -> assertThat(response.jsonPath().getString("alg")).isNotNull(),
                    () -> assertThat(response.jsonPath().getString("value")).isNotNull());

            // And check value

            String value = response.jsonPath().getString("value");

            Matcher publicKeyMatcher = RSA_PUBLIC_KEY.matcher(value);

            Assert.isTrue(publicKeyMatcher.lookingAt(), "Pattern is invalid");

            final byte[] content = Base64.decodeBase64(publicKeyMatcher.group(1).getBytes(StandardCharsets.UTF_8));

            KeyFactory fact = KeyFactory.getInstance("RSA");
            KeySpec keySpec = new X509EncodedKeySpec(content);
            PublicKey publicKey = fact.generatePublic(keySpec);

            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);

            JWTVerifier verifier = JWT.require(algorithm).withAudience("app1").build();
            Payload payload = verifier.verify(accessToken);

            assertAll(
                    () -> assertThat(payload.getClaim("aud").asArray(String.class)).contains("app1"),
                    () -> assertThat(payload.getClaim("authorities").asArray(String.class)).contains("ROLE_APP"),
                    () -> assertThat(payload.getClaim("scope").asArray(String.class)).contains("account:create"));

        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    @TestMethodOrder(OrderAnnotation.class)
    class AuthorizationImplicit {

        private String accessToken;

        private String username;

        private String xAuthToken;

        @BeforeAll
        void username() {

            username = "jean.dupond@gmail.com";
        }

        @Test
        @Order(0)
        void credentials() {

            // Given client credentials

            Map<String, String> params = new HashMap<>();
            params.put("grant_type", "client_credentials");

            // When perform get access token

            Response response = requestSpecification.auth().basic("test", "secret").formParams(params)
                    .post(restTemplate.getRootUri() + "/oauth/token");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                    () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

            accessToken = response.jsonPath().getString("access_token");

        }

        @Order(1)
        @Test
        void login() {

            // Given mock login resource

            LoginEntity account = new LoginEntity();
            account.setUsername(username);
            account.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));

            Mockito.when(resource.get(username)).thenReturn(Optional.of(account));

            // When perform login

            Response response = requestSpecification.header("Authorization", "Bearer " + accessToken)
                    .formParams("username", username, "password", "123")
                    .post(restTemplate.getRootUri() + "/login");

            // Then check response

            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value()),
                    () -> assertThat(response.getHeader("X-Auth-Token")).isNotNull(),
                    () -> assertThat(response.getCookies()).isEmpty());

            xAuthToken = response.getHeader("X-Auth-Token");
        }

        @Order(2)
        @Test
        void authorize() {

            // When perform authorize

            String authorizeUrl = restTemplate.getRootUri() + "/oauth/authorize?response_type=token&client_id=mobile";
            Response response = requestSpecification.when().redirects().follow(false).header("X-Auth-Token", xAuthToken).get(authorizeUrl);

            // Then check response
            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SEE_OTHER.value()),
                    () -> assertThat(response.getHeader(HttpHeaders.LOCATION)).isNotNull());

            String location = response.getHeader(HttpHeaders.LOCATION);

            // And check access token

            accessToken = location.split("#|=|&")[2];
            assertThat(accessToken).isNotNull();
        }

        @Order(3)
        @Test
        void checkToken() {

            // When perform check token

            Map<String, String> params = new HashMap<>();
            params.put("token", accessToken);

            Response response = requestSpecification.auth().basic("resource", "secret").formParams(params)
                    .post(restTemplate.getRootUri() + "/oauth/check_token");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

            // And check payload

            JWTPartsParser parser = new JWTParser();
            Payload payload = parser.parsePayload(response.getBody().print());

            assertAll(
                    () -> assertThat(payload.getClaim("user_name").asString()).isEqualTo(username),
                    () -> assertThat(payload.getSubject()).isEqualTo(username),
                    () -> assertThat(payload.getClaim("aud").asArray(String.class)).contains("app1"),
                    () -> assertThat(payload.getClaim("authorities").asArray(String.class)).contains("ROLE_ACCOUNT"),
                    () -> assertThat(payload.getClaim("scope").asArray(String.class)).contains("account:read"));

        }

    }

    @Nested
    class AuthorizationByPassword {

        @Nested
        @TestInstance(TestInstance.Lifecycle.PER_CLASS)
        @TestMethodOrder(OrderAnnotation.class)
        class User {

            private String username;

            private String accessToken;

            private String refreshToken;

            @BeforeAll
            void username() {

                username = "jean.dupond@gmail.com";
            }

            @Order(0)
            @Test
            void password() {

                // Given mock login resource

                LoginEntity account = new LoginEntity();
                account.setUsername(username);
                account.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));

                Mockito.when(resource.get(username)).thenReturn(Optional.of(account));

                // When perform get access token

                Map<String, String> params = new HashMap<>();
                params.put("grant_type", "password");
                params.put("username", username);
                params.put("password", "123");
                params.put("client_id", "test_user");
                params.put("redirect_uri", "xxx");

                Response response = requestSpecification.auth().basic("test_user", "secret").formParams(params)
                        .post(restTemplate.getRootUri() + "/oauth/token");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                        () -> assertThat(response.jsonPath().getString("access_token")).isNotNull(),
                        () -> assertThat(response.jsonPath().getString("refresh_token")).isNotNull());

                accessToken = response.jsonPath().getString("access_token");
                refreshToken = response.jsonPath().getString("refresh_token");

            }

            @Order(1)
            @Test
            void checkToken() {

                // When perform check token

                Map<String, String> params = new HashMap<>();
                params.put("token", accessToken);

                Response response = requestSpecification.auth().basic("resource", "secret").formParams(params)
                        .post(restTemplate.getRootUri() + "/oauth/check_token");

                // Then check response

                assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

                // And check payload

                JWTPartsParser parser = new JWTParser();
                Payload payload = parser.parsePayload(response.getBody().print());

                assertAll(
                        () -> assertThat(payload.getClaim("aud").asArray(String.class)).contains("app1"),
                        () -> assertThat(payload.getClaim("authorities").asArray(String.class)).contains("ROLE_ACCOUNT"),
                        () -> assertThat(payload.getClaim("scope").asArray(String.class)).contains("account:read", "account:update"));

            }

            @Order(1)
            @Test
            void refreshToken() {

                // Given mock login resource

                LoginEntity account = new LoginEntity();
                account.setUsername(username);
                account.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));

                Mockito.when(resource.get(username)).thenReturn(Optional.of(account));

                // When perform refresh token

                Map<String, String> params = new HashMap<>();
                params.put("grant_type", "refresh_token");
                params.put("client_id", "test_user");
                params.put("refresh_token", refreshToken);

                Response response = requestSpecification.auth().basic("test_user", "secret").formParams(params)
                        .post(restTemplate.getRootUri() + "/oauth/token");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                        () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());
            }

            private Stream<Arguments> passwordFailure() {

                LoginEntity account1 = new LoginEntity();
                account1.setUsername("jean.dupond@gmail.com");
                account1.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));
                account1.setDisabled(true);

                LoginEntity account2 = new LoginEntity();
                account2.setUsername("jean.dupond@gmail.com");
                account2.setPassword("{bcrypt}" + BCrypt.hashpw("124", BCrypt.gensalt()));

                LoginEntity account3 = new LoginEntity();
                account3.setUsername("jean.dupond@gmail.com");
                account3.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));
                account3.setAccountLocked(true);

                return Stream.of(
                        Arguments.of(Optional.empty(), HttpStatus.UNAUTHORIZED, "Bad Credentials"),
                        Arguments.of(Optional.of(account1), HttpStatus.BAD_REQUEST, "User is disabled"),
                        Arguments.of(Optional.of(account2), HttpStatus.UNAUTHORIZED, "Bad Credentials"),
                        Arguments.of(Optional.of(account3), HttpStatus.BAD_REQUEST, "User account is locked"));
            }

            @ParameterizedTest
            @MethodSource
            void passwordFailure(Optional<LoginEntity> loginResponse, HttpStatus expectedStatus, String expectedError) {

                // Given mock login resource

                Mockito.when(resource.get(username)).thenReturn(loginResponse);

                // When perform get access token

                Map<String, String> params = new HashMap<>();
                params.put("grant_type", "password");
                params.put("username", username);
                params.put("password", "123");
                params.put("client_id", "test_user");
                params.put("redirect_uri", "xxx");

                Response response = requestSpecification.auth().basic("test_user", "secret").formParams(params)
                        .post(restTemplate.getRootUri() + "/oauth/token");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(expectedStatus.value()),
                        () -> assertThat(response.jsonPath().getString("error_description")).isEqualTo(expectedError));

            }

        }

        @Nested
        @TestInstance(TestInstance.Lifecycle.PER_CLASS)
        @TestMethodOrder(OrderAnnotation.class)
        class Back {

            private String accessToken;

            @Order(0)
            @Test
            void password() {

                // When perform get access token

                Map<String, String> params = new HashMap<>();
                params.put("grant_type", "password");
                params.put("username", "admin");
                params.put("password", "admin123");
                params.put("client_id", "back_user");
                params.put("redirect_uri", "xxx");

                Response response = requestSpecification.auth().basic("back_user", "secret").formParams(params)
                        .post(restTemplate.getRootUri() + "/oauth/token");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value()),
                        () -> assertThat(response.jsonPath().getString("access_token")).isNotNull());

                accessToken = response.jsonPath().getString("access_token");

            }

            @Test
            void passwordBackFailure() {

                // When perform get access token

                Map<String, String> params = new HashMap<>();
                params.put("grant_type", "password");
                params.put("username", "bad_login");
                params.put("password", "admin123");
                params.put("client_id", "back_user");
                params.put("redirect_uri", "xxx");

                Response response = requestSpecification.auth().basic("back_user", "secret").formParams(params)
                        .post(restTemplate.getRootUri() + "/oauth/token");

                // Then check response

                assertAll(
                        () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value()),
                        () -> assertThat(response.jsonPath().getString("error")).isEqualTo("unauthorized"));
            }

            @Order(1)
            @Test
            void checkToken() {

                // When perform check token

                Map<String, String> params = new HashMap<>();
                params.put("token", accessToken);

                Response response = requestSpecification.auth().basic("resource", "secret").formParams(params)
                        .post(restTemplate.getRootUri() + "/oauth/check_token");

                // Then check response

                assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

                // And check payload

                JWTPartsParser parser = new JWTParser();
                Payload payload = parser.parsePayload(response.getBody().print());

                assertAll(
                        () -> assertThat(payload.getClaim("aud").asArray(String.class)).contains("app1"),
                        () -> assertThat(payload.getClaim("authorities").asArray(String.class)).contains("ROLE_BACK"),
                        () -> assertThat(payload.getClaim("scope").asArray(String.class)).contains("stock:read", "stock:update"));

            }

        }

    }
}