package com.exemple.authorization.login;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.net.URI;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mindrot.jbcrypt.BCrypt;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;

import com.exemple.authorization.common.JsonNodeUtils;
import com.exemple.authorization.common.LoggingFilter;
import com.exemple.authorization.core.AuthorizationTestConfiguration;
import com.exemple.authorization.resource.login.LoginResource;
import com.exemple.authorization.resource.login.exception.UsernameAlreadyExistsException;
import com.exemple.authorization.resource.login.model.LoginEntity;
import com.fasterxml.jackson.databind.JsonNode;
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
class LoginApiTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private JWSSigner algorithm;

    @Autowired
    private LoginResource loginResource;

    private RequestSpecification requestSpecification;

    public static final String URL = "/ws/v1/logins";

    @BeforeEach
    private void before() {

        Mockito.reset(loginResource);

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG));

    }

    @Test
    void check() throws JOSEException {

        // Given login

        String username = "jean.dupond@gmail.com";

        // And token

        var payload = new JWTClaimsSet.Builder()
                .claim("scope", new String[] { "login:head" })
                .claim("client_id", "clientId1")
                .jwtID(UUID.randomUUID().toString())
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        // And mock service

        Mockito.when(loginResource.get(username)).thenReturn(Optional.of(new LoginEntity()));

        // When perform head

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "app")
                .head(restTemplate.getRootUri() + URL + "/" + username);

        // Then check status

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT.value());

        // And check mock

        Mockito.verify(loginResource).get(username);

    }

    @Test
    void checkNotFound() throws JOSEException {

        // Given login

        String username = "jean.dupond@gmail.com";

        // And token

        var payload = new JWTClaimsSet.Builder()
                .claim("scope", new String[] { "login:head" })
                .claim("client_id", "clientId1")
                .jwtID(UUID.randomUUID().toString())
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        // And mock service

        Mockito.when(loginResource.get(username)).thenReturn(Optional.empty());

        // When perform head

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "app")
                .head(restTemplate.getRootUri() + URL + "/" + username);

        // Then check status

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND.value());

        // And check mock

        Mockito.verify(loginResource).get(username);

    }

    @Test
    void create() throws UsernameAlreadyExistsException, JOSEException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And mock service

        Mockito.when(loginResource.get(username)).thenReturn(Optional.empty());

        // And token

        var payload = new JWTClaimsSet.Builder()
                .claim("scope", new String[] { "login:update" })
                .claim("client_id", "clientId1")
                .jwtID(UUID.randomUUID().toString())
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        // When perform post

        Map<String, Object> login = Map.of("password", "mdp123");

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "app")
                .body(login).put(restTemplate.getRootUri() + URL + "/" + username);

        // Then check response

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED.value()),
                () -> assertThat(response.getHeader("Location")).isEqualTo(URI.create(restTemplate.getRootUri() + URL + "/" + username).toString()));

        // And check service

        ArgumentCaptor<LoginEntity> entity = ArgumentCaptor.forClass(LoginEntity.class);
        Mockito.verify(loginResource).save(entity.capture());

        assertAll(
                () -> assertThat(entity.getValue().getUsername()).isEqualTo(username),
                () -> assertThat(entity.getValue().getPassword()).startsWith("{bcrypt}"),
                () -> assertThat(BCrypt.checkpw("mdp123", entity.getValue().getPassword().substring("{bcrypt}".length()))).isTrue());

        // And check mock

        Mockito.verify(loginResource).get(username);

    }

    @Test
    void createFailsBecauseUsernameAlreadyExists() throws UsernameAlreadyExistsException, JOSEException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And mock service

        Mockito.when(loginResource.get(username)).thenReturn(Optional.empty());
        Mockito.doThrow(new UsernameAlreadyExistsException(username)).when(loginResource).save(Mockito.any());

        // And token

        var payload = new JWTClaimsSet.Builder()
                .claim("scope", new String[] { "login:update" })
                .claim("client_id", "clientId1")
                .jwtID(UUID.randomUUID().toString())
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        // When perform post

        Map<String, Object> login = Map.of("password", "mdp123");

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "app")
                .body(login).put(restTemplate.getRootUri() + URL + "/" + username);

        // Then check status

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());

        // And check message

        JsonNode expectedMessage = JsonNodeUtils.create(() -> {

            Map<String, Object> model = Map.of(
                    "path", "/username",
                    "code", "username",
                    "message", "[" + username + "] already exists");

            return Collections.singletonList(model);

        });
        JsonNode message = response.as(JsonNode.class);
        assertThat(message).isEqualTo(expectedMessage);

    }

    @Test
    void update() throws UsernameAlreadyExistsException, JOSEException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And mock service

        LoginEntity entity = new LoginEntity();
        entity.setUsername(username);
        entity.setPassword("mdp123");
        entity.setDisabled(true);
        entity.setAccountLocked(true);

        Mockito.when(loginResource.get(username)).thenReturn(Optional.of(entity));

        // And token

        var payload = new JWTClaimsSet.Builder()
                .subject(username)
                .claim("scope", new String[] { "login:update" })
                .claim("client_id", "clientId1")
                .jwtID(UUID.randomUUID().toString())
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        // When perform post

        Map<String, Object> login = Map.of("password", "mdp124");

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "app")
                .body(login).put(restTemplate.getRootUri() + URL + "/" + username);

        // Then check status

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT.value());

        // And check service

        ArgumentCaptor<LoginEntity> actualEntity = ArgumentCaptor.forClass(LoginEntity.class);
        Mockito.verify(loginResource).update(actualEntity.capture());

        assertAll(
                () -> assertThat(actualEntity.getValue().getUsername()).isEqualTo(username),
                () -> assertThat(actualEntity.getValue().getPassword()).startsWith("{bcrypt}"),
                () -> assertThat(BCrypt.checkpw("mdp124", actualEntity.getValue().getPassword().substring("{bcrypt}".length()))).isTrue(),
                () -> assertThat(actualEntity.getValue().isDisabled()).isTrue(),
                () -> assertThat(actualEntity.getValue().isAccountLocked()).isTrue());

        // And check mock

        Mockito.verify(loginResource).get(username);

    }

    @Test
    void updateForbidden() throws UsernameAlreadyExistsException, JOSEException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And mock service

        LoginEntity entity = new LoginEntity();
        entity.setUsername(username);

        Mockito.when(loginResource.get(username)).thenReturn(Optional.of(entity));

        // And token

        var payload = new JWTClaimsSet.Builder()
                .subject("jean.dupont@gmail.com")
                .claim("scope", new String[] { "login:update" })
                .claim("client_id", "clientId1")
                .jwtID(UUID.randomUUID().toString())
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        // When perform post

        Map<String, Object> login = Map.of("password", "mdp124");

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "app")
                .body(login).put(restTemplate.getRootUri() + URL + "/" + username);

        // Then check status

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());

        // And check mock
        Mockito.verify(loginResource, Mockito.never()).update(Mockito.any());
        Mockito.verify(loginResource).get(username);

    }

    @Test
    void move() throws UsernameAlreadyExistsException, JOSEException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And mock service

        LoginEntity entity = new LoginEntity();
        entity.setUsername(username);
        entity.setPassword("mdp123");
        entity.setDisabled(true);
        entity.setAccountLocked(true);

        Mockito.when(loginResource.get(username)).thenReturn(Optional.of(entity));

        // And token

        var payload = new JWTClaimsSet.Builder()
                .subject(username)
                .claim("scope", new String[] { "login:update" })
                .claim("client_id", "clientId1")
                .jwtID(UUID.randomUUID().toString())
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        // When perform post

        Map<String, Object> login = Map.of(
                "fromUsername", username,
                "toUsername", "jean.dupont@gmail.com");

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "app")
                .body(login).post(restTemplate.getRootUri() + URL + "/move");

        // Then check response

        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED.value()),
                () -> assertThat(response.getHeader("Location"))
                        .isEqualTo(URI.create(restTemplate.getRootUri() + URL + "/jean.dupont@gmail.com").toString()));

        // And check service

        ArgumentCaptor<LoginEntity> entityCaptor = ArgumentCaptor.forClass(LoginEntity.class);
        Mockito.verify(loginResource).save(entityCaptor.capture());

        assertAll(
                () -> assertThat(entityCaptor.getValue().getUsername()).isEqualTo("jean.dupont@gmail.com"),
                () -> assertThat(entityCaptor.getValue().getPassword()).isEqualTo("mdp123"),
                () -> assertThat(entityCaptor.getValue().isDisabled()).isTrue(),
                () -> assertThat(entityCaptor.getValue().isAccountLocked()).isTrue());

        // And check mock

        Mockito.verify(loginResource).get(username);

        // And check mock

        Mockito.verify(loginResource).delete(username);

    }

    @Test
    void moveFailsBecauseUsernameAlreadyExists() throws UsernameAlreadyExistsException, JOSEException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And mock service

        Mockito.when(loginResource.get(username)).thenReturn(Optional.of(new LoginEntity()));
        Mockito.doThrow(new UsernameAlreadyExistsException(username)).when(loginResource).save(Mockito.any());

        // And token

        var payload = new JWTClaimsSet.Builder()
                .subject(username)
                .claim("scope", new String[] { "login:update" })
                .claim("client_id", "clientId1")
                .jwtID(UUID.randomUUID().toString())
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        // When perform post

        Map<String, Object> login = Map.of(
                "fromUsername", username,
                "toUsername", "jean.dupont@gmail.com");

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "app")
                .body(login).post(restTemplate.getRootUri() + URL + "/move");

        // Then check status

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());

        // And check message

        JsonNode expectedMessage = JsonNodeUtils.create(() -> {

            Map<String, Object> model = Map.of(
                    "path", "/toUsername",
                    "code", "username",
                    "message", "[" + username + "] already exists");

            return Collections.singletonList(model);

        });
        JsonNode message = response.as(JsonNode.class);
        assertThat(message).isEqualTo(expectedMessage);

    }

    @Test
    void moveFailsBecauseUsernameNotFound() throws UsernameAlreadyExistsException, JOSEException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And mock service

        Mockito.when(loginResource.get(username)).thenReturn(Optional.empty());

        // And token

        var payload = new JWTClaimsSet.Builder()
                .subject(username)
                .claim("scope", new String[] { "login:update" })
                .claim("client_id", "clientId1")
                .jwtID(UUID.randomUUID().toString())
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        // When perform post

        Map<String, Object> login = Map.of(
                "fromUsername", username,
                "toUsername", "jean.dupont@gmail.com");

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "app")
                .body(login).post(restTemplate.getRootUri() + URL + "/move");

        // Then check status

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());

        // And check message

        JsonNode expectedMessage = JsonNodeUtils.create(() -> {

            Map<String, Object> model = Map.of(
                    "path", "/fromUsername",
                    "code", "not_found",
                    "message", "[" + username + "] not found");

            return Collections.singletonList(model);

        });
        JsonNode message = response.as(JsonNode.class);
        assertThat(message).isEqualTo(expectedMessage);

    }

    @Test
    void moveFailsBecauseForbidden() throws UsernameAlreadyExistsException, JOSEException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And token

        var payload = new JWTClaimsSet.Builder()
                .subject("jean.dupont@gmail.com")
                .claim("scope", new String[] { "login:update" })
                .claim("client_id", "clientId1")
                .jwtID(UUID.randomUUID().toString())
                .build();

        var accessToken = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload);
        accessToken.sign(algorithm);

        // When perform post

        Map<String, Object> login = Map.of(
                "fromUsername", username,
                "toUsername", "jean.dupont@gmail.com");

        Response response = requestSpecification.contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + accessToken.serialize())
                .header("app", "app")
                .body(login).post(restTemplate.getRootUri() + URL + "/move");

        // Then check status

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());

    }

}
