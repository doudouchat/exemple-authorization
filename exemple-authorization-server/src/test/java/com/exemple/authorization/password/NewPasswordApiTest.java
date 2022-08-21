package com.exemple.authorization.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import javax.ws.rs.core.SecurityContext;

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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.JWTPartsParser;
import com.auth0.jwt.interfaces.Payload;
import com.exemple.authorization.common.LoggingFilter;
import com.exemple.authorization.core.AuthorizationTestConfiguration;
import com.exemple.authorization.core.client.AuthorizationClientBuilder;
import com.exemple.authorization.core.feature.FeatureTestConfiguration.TestFilter;
import com.exemple.authorization.resource.login.LoginResource;
import com.exemple.authorization.resource.login.model.LoginEntity;

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
    private TestFilter testFilter;

    @Autowired
    private LoginResource loginResource;

    @Autowired
    private AuthorizationClientBuilder authorizationClientBuilder;

    @Autowired
    private Algorithm algorithm;

    @Autowired
    private Clock clock;

    @Value("${authorization.password.expiryTime}")
    private long expiryTime;

    private RequestSpecification requestSpecification;

    @BeforeAll
    private void init() throws Exception {

        String password = "{bcrypt}" + BCrypt.hashpw("secret", BCrypt.gensalt());

        authorizationClientBuilder

                .withClient("test").secret(password).authorizedGrantTypes("client_credentials").redirectUris("xxx").scopes("account:create")
                .autoApprove("account:create").authorities("ROLE_APP").resourceIds("app1")

                .and()

                .withClient("clientId1").secret(password).authorizedGrantTypes("password", "authorization_code", "refresh_token").redirectUris("xxx")
                .scopes("account:read", "account:update").autoApprove("account:read", "account:update").authorities("ROLE_APP").resourceIds("app1")

                .and()

                .withClient("resource").secret(password).authorizedGrantTypes("client_credentials").authorities("ROLE_TRUSTED_CLIENT")

                .and().build();

    }

    @BeforeEach
    private void before() {

        Mockito.reset(loginResource);

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG));

    }

    @Nested
    class Password {

        @Test
        void password() {

            // Given token

            String accessToken = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_APP" }).withAudience("app")
                    .withClaim("client_id", "clientId1").sign(algorithm);

            // And given username

            String username = "jean.dupond@gmail.com";

            // And mock login resource

            LoginEntity account = new LoginEntity();
            account.setUsername(username);

            Map<String, Object> newPassword = Map.of("login", username);

            Mockito.when(loginResource.get(username)).thenReturn(Optional.of(account));

            // When perform create password

            Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken)
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
        void passwordTrustedClient() {

            // Given token

            String accessToken = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_TRUSTED_CLIENT" }).withAudience("app1", "app2")
                    .withClaim("client_id", "clientId1").sign(algorithm);

            // And mock login resource

            LoginEntity account = new LoginEntity();
            account.setUsername(username);

            Map<String, Object> newPassword = Map.of("login", username);

            Mockito.when(loginResource.get(username)).thenReturn(Optional.of(account));

            // When perform create password

            Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken)
                    .header("app", "app1")
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
        void checkToken() {

            // When perform check token

            Map<String, String> params = Map.of("token", token);

            Response response = requestSpecification.auth().basic("resource", "secret").formParams(params)
                    .post(restTemplate.getRootUri() + "/oauth/check_token");

            // Then check response

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());

            // And check payload

            JWTPartsParser parser = new JWTParser();
            Payload payload = parser.parsePayload(response.getBody().print());

            assertAll(
                    () -> assertThat(payload.getSubject()).isEqualTo(username),
                    () -> assertThat(payload.getClaim("authorities").asArray(String.class)).contains("ROLE_TRUSTED_CLIENT"),
                    () -> assertThat(payload.getClaim("scope").asArray(String.class)).contains("login:read", "login:update"),
                    () -> assertThat(payload.getExpiresAt()).isEqualTo(Date.from(Instant.now(clock).plusSeconds(expiryTime))),
                    () -> assertThat(payload.getId()).isNotNull());

        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class PasswordFailure {

        private Stream<Arguments> passwordFailureForbidden() {

            String accessToken1 = JWT.create().withClaim("client_id", "clientId1").withArrayClaim("authorities", new String[] { "ROLE_ACCOUNT" })
                    .withAudience("app").sign(algorithm);
            String accessToken2 = JWT.create().withClaim("client_id", "clientId1")
                    .withExpiresAt(new Date(Instant.now().minus(1, ChronoUnit.HOURS).toEpochMilli()))
                    .withArrayClaim("authorities", new String[] { "ROLE_APP" }).sign(algorithm);
            String accessToken3 = JWT.create().withClaim("client_id", "clientId1").withArrayClaim("authorities", new String[] { "ROLE_APP" })
                    .sign(algorithm);
            String accessToken4 = JWT.create().withClaim("client_id", "clientId1").withAudience("app").sign(algorithm);
            String accessToken5 = JWT.create().withClaim("client_id", "other").withArrayClaim("authorities", new String[] { "ROLE_TRUSTED_CLIENT" })
                    .withAudience("app1", "app2").sign(algorithm);

            return Stream.of(
                    // not authorities to access
                    Arguments.of("Authorization", "Bearer " + accessToken1, HttpStatus.FORBIDDEN),
                    // token is expired
                    Arguments.of("Authorization", "Bearer " + accessToken2, HttpStatus.UNAUTHORIZED),
                    // not bearer
                    Arguments.of("Authorization", accessToken3, HttpStatus.FORBIDDEN),
                    // not token
                    Arguments.of("Header", "Bearer " + accessToken3, HttpStatus.FORBIDDEN),
                    // auhorities is empty
                    Arguments.of("Authorization", "Bearer " + accessToken4, HttpStatus.FORBIDDEN),
                    // token no recognized
                    Arguments.of("Authorization", "Bearer toto", HttpStatus.UNAUTHORIZED),
                    // bad client id
                    Arguments.of("Authorization", "Bearer " + accessToken5, HttpStatus.UNAUTHORIZED));
        }

        @ParameterizedTest
        @MethodSource
        void passwordFailureForbidden(String header, String headerValue, HttpStatus expectedStatus) {

            String login = "jean.dupond@gmail.com";

            Map<String, Object> newPassword = Map.of("login", login);

            Response response = requestSpecification.contentType(ContentType.JSON).header(header, headerValue).header("app", "app").body(newPassword)
                    .post(restTemplate.getRootUri() + "/ws/v1/new_password");

            assertThat(response.getStatusCode()).isEqualTo(expectedStatus.value());

        }

        @Test
        void passwordFailureBadRequest() {

            String accessToken = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_APP" }).withAudience("app")
                    .withClaim("client_id", "clientId1").sign(algorithm);

            Map<String, Object> newPassword = Map.of("login", "");

            Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken)
                    .header("app", "app")
                    .body(newPassword).post(restTemplate.getRootUri() + "/ws/v1/new_password");

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());

        }
    }

}
