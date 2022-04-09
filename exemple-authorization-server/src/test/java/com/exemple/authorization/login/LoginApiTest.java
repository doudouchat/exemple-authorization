package com.exemple.authorization.login;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;

import org.mindrot.jbcrypt.BCrypt;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.exemple.authorization.common.JsonNodeUtils;
import com.exemple.authorization.common.LoggingFilter;
import com.exemple.authorization.core.AuthorizationTestConfiguration;
import com.exemple.authorization.resource.login.LoginResource;
import com.exemple.authorization.resource.login.exception.UsernameAlreadyExistsException;
import com.exemple.authorization.resource.login.model.LoginEntity;
import com.fasterxml.jackson.databind.JsonNode;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

@SpringBootTest(classes = { AuthorizationTestConfiguration.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
public class LoginApiTest extends AbstractTestNGSpringContextTests {

    private static final Logger LOG = LoggerFactory.getLogger(LoginApiTest.class);

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private LoginResource loginResource;

    @Autowired
    private Algorithm algorithm;

    @Value("${authorization.password.expiryTime}")
    private long expiryTime;

    private RequestSpecification requestSpecification;

    public static final String URL = "/ws/v1/logins";

    @BeforeMethod
    private void before() {

        Mockito.reset(loginResource);

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG));

    }

    @Test
    public void check() {

        // Given login

        String username = "jean.dupond@gmail.com";

        // And token

        String accessToken = JWT.create().withArrayClaim("scope", new String[] { "login:head" }).withClaim("client_id", "clientId1").sign(algorithm);

        // And mock service

        Mockito.when(loginResource.get(Mockito.eq(username))).thenReturn(Optional.of(new LoginEntity()));

        // When perform head

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .head(restTemplate.getRootUri() + URL + "/" + username);

        // Then check status

        assertThat(response.getStatusCode(), is(HttpStatus.NO_CONTENT.value()));

        // And check mock

        Mockito.verify(loginResource).get(Mockito.eq(username));

    }

    @Test
    public void checkNotFound() {

        // Given login

        String username = "jean.dupond@gmail.com";

        // And token

        String accessToken = JWT.create().withArrayClaim("scope", new String[] { "login:head" }).withClaim("client_id", "clientId1").sign(algorithm);

        // And mock service

        Mockito.when(loginResource.get(Mockito.eq(username))).thenReturn(Optional.empty());

        // When perform head

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .head(restTemplate.getRootUri() + URL + "/" + username);

        // Then check status

        assertThat(response.getStatusCode(), is(HttpStatus.NOT_FOUND.value()));

        // And check mock

        Mockito.verify(loginResource).get(Mockito.eq(username));

    }

    @Test
    public void create() throws UsernameAlreadyExistsException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And mock service

        Mockito.when(loginResource.get(Mockito.eq(username))).thenReturn(Optional.empty());

        // And token

        String accessToken = JWT.create().withArrayClaim("scope", new String[] { "login:update" }).withClaim("client_id", "clientId1")
                .sign(algorithm);

        // When perform post

        Map<String, Object> login = new HashMap<>();
        login.put("password", "mdp123");
        login.put("disabled", true);
        login.put("accountLocked", true);
        login.put("roles", Arrays.asList("role1", "role2"));

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .body(login).put(restTemplate.getRootUri() + URL + "/" + username);

        // Then check status

        assertThat(response.getStatusCode(), is(HttpStatus.CREATED.value()));

        // And check location

        assertThat(response.getHeader("Location"), is(URI.create(restTemplate.getRootUri() + URL + "/" + username).toString()));

        // And check service

        ArgumentCaptor<LoginEntity> entity = ArgumentCaptor.forClass(LoginEntity.class);
        Mockito.verify(loginResource).save(entity.capture());

        assertThat(entity.getValue().getUsername(), is(username));
        assertThat(entity.getValue().getPassword(), startsWith("{bcrypt}"));
        assertThat(BCrypt.checkpw("mdp123", entity.getValue().getPassword().substring("{bcrypt}".length())), is(true));
        assertThat(entity.getValue().getRoles(), containsInAnyOrder("role1", "role2"));
        assertThat(entity.getValue().isDisabled(), is(true));
        assertThat(entity.getValue().isAccountLocked(), is(true));

        // And check mock

        Mockito.verify(loginResource).get(Mockito.eq(username));

    }

    @Test
    public void createFailsBecauseUsernameAlreadyExists() throws UsernameAlreadyExistsException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And mock service

        Mockito.when(loginResource.get(Mockito.eq(username))).thenReturn(Optional.empty());
        Mockito.doThrow(new UsernameAlreadyExistsException(username)).when(loginResource).save(Mockito.any());

        // And token

        String accessToken = JWT.create().withArrayClaim("scope", new String[] { "login:update" }).withClaim("client_id", "clientId1")
                .sign(algorithm);

        // When perform post

        Map<String, Object> login = new HashMap<>();
        login.put("password", "mdp123");

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .body(login).put(restTemplate.getRootUri() + URL + "/" + username);

        // Then check status

        assertThat(response.getStatusCode(), is(HttpStatus.BAD_REQUEST.value()));

        // And check message

        JsonNode expectedMessage = JsonNodeUtils.create(() -> {

            Map<String, Object> model = new HashMap<>();
            model.put("path", "/username");
            model.put("code", "username");
            model.put("message", "[" + username + "] already exists");

            return Collections.singletonList(model);

        });
        JsonNode message = response.as(JsonNode.class);
        assertThat(message, is(expectedMessage));

    }

    @Test
    public void update() throws UsernameAlreadyExistsException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And mock service

        LoginEntity entity = new LoginEntity();
        entity.setUsername(username);
        entity.setPassword("mdp123");
        entity.setDisabled(true);
        entity.setAccountLocked(true);
        entity.setRoles(new HashSet<>(Arrays.asList("role1", "role2")));

        Mockito.when(loginResource.get(Mockito.eq(username))).thenReturn(Optional.of(entity));

        // And token

        String accessToken = JWT.create().withSubject(username).withArrayClaim("scope", new String[] { "login:update" })
                .withClaim("client_id", "clientId1").sign(algorithm);

        // When perform post

        Map<String, Object> login = new HashMap<>();
        login.put("password", "mdp124");
        login.put("disabled", false);
        login.put("accountLocked", false);
        login.put("roles", Arrays.asList("role1", "role3"));

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .body(login).put(restTemplate.getRootUri() + URL + "/" + username);

        // Then check status

        assertThat(response.getStatusCode(), is(HttpStatus.NO_CONTENT.value()));

        // And check service

        ArgumentCaptor<LoginEntity> actualEntity = ArgumentCaptor.forClass(LoginEntity.class);
        Mockito.verify(loginResource).update(actualEntity.capture());

        assertThat(actualEntity.getValue().getUsername(), is(username));
        assertThat(actualEntity.getValue().getPassword(), startsWith("{bcrypt}"));
        assertThat(BCrypt.checkpw("mdp124", actualEntity.getValue().getPassword().substring("{bcrypt}".length())), is(true));
        assertThat(actualEntity.getValue().getRoles(), containsInAnyOrder("role1", "role3"));
        assertThat(actualEntity.getValue().isDisabled(), is(false));
        assertThat(actualEntity.getValue().isAccountLocked(), is(false));

        // And check mock

        Mockito.verify(loginResource).get(Mockito.eq(username));

    }

    @Test
    public void updateForbidden() throws UsernameAlreadyExistsException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And mock service

        LoginEntity entity = new LoginEntity();
        entity.setUsername(username);

        Mockito.when(loginResource.get(Mockito.eq(username))).thenReturn(Optional.of(entity));

        // And token

        String accessToken = JWT.create().withSubject("jean.dupont@gmail.com").withArrayClaim("scope", new String[] { "login:update" })
                .withClaim("client_id", "clientId1").sign(algorithm);

        // When perform post

        Map<String, Object> login = new HashMap<>();
        login.put("password", "mdp124");
        login.put("disabled", false);
        login.put("accountLocked", false);
        login.put("roles", Arrays.asList("role1", "role3"));

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .body(login).put(restTemplate.getRootUri() + URL + "/" + username);

        // Then check status

        assertThat(response.getStatusCode(), is(HttpStatus.FORBIDDEN.value()));

        // And check mock
        Mockito.verify(loginResource, Mockito.never()).update(Mockito.any());
        Mockito.verify(loginResource).get(Mockito.eq(username));

    }

    @Test
    public void move() throws UsernameAlreadyExistsException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And mock service

        // And mock service

        LoginEntity entity = new LoginEntity();
        entity.setUsername(username);
        entity.setPassword("mdp123");
        entity.setDisabled(true);
        entity.setAccountLocked(true);
        entity.setRoles(new HashSet<>(Arrays.asList("role1", "role2")));

        Mockito.when(loginResource.get(Mockito.eq(username))).thenReturn(Optional.of(entity));

        // And token

        String accessToken = JWT.create().withSubject(username).withArrayClaim("scope", new String[] { "login:update" })
                .withClaim("client_id", "clientId1").sign(algorithm);

        // When perform post

        Map<String, Object> login = new HashMap<>();
        login.put("fromUsername", username);
        login.put("toUsername", "jean.dupont@gmail.com");

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .body(login).post(restTemplate.getRootUri() + URL + "/move");

        // Then check status

        assertThat(response.getStatusCode(), is(HttpStatus.CREATED.value()));

        // And check location

        assertThat(response.getHeader("Location"), is(URI.create(restTemplate.getRootUri() + URL + "/jean.dupont@gmail.com").toString()));

        // And check service

        ArgumentCaptor<LoginEntity> entityCaptor = ArgumentCaptor.forClass(LoginEntity.class);
        Mockito.verify(loginResource).save(entityCaptor.capture());

        assertThat(entityCaptor.getValue().getUsername(), is("jean.dupont@gmail.com"));
        assertThat(entityCaptor.getValue().getPassword(), is("mdp123"));
        assertThat(entityCaptor.getValue().isDisabled(), is(true));
        assertThat(entityCaptor.getValue().isAccountLocked(), is(true));

        // And check mock

        Mockito.verify(loginResource).get(Mockito.eq(username));

        // And check mock

        Mockito.verify(loginResource).delete(Mockito.eq(username));

    }

    @Test
    public void moveFailsBecauseUsernameAlreadyExists() throws UsernameAlreadyExistsException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And mock service

        Mockito.when(loginResource.get(Mockito.eq(username))).thenReturn(Optional.of(new LoginEntity()));
        Mockito.doThrow(new UsernameAlreadyExistsException(username)).when(loginResource).save(Mockito.any());

        // And token

        String accessToken = JWT.create().withSubject(username).withArrayClaim("scope", new String[] { "login:update" })
                .withClaim("client_id", "clientId1").sign(algorithm);

        // When perform post

        Map<String, Object> login = new HashMap<>();
        login.put("fromUsername", username);
        login.put("toUsername", "jean.dupont@gmail.com");

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .body(login).post(restTemplate.getRootUri() + URL + "/move");

        // Then check status

        assertThat(response.getStatusCode(), is(HttpStatus.BAD_REQUEST.value()));

        // And check message

        JsonNode expectedMessage = JsonNodeUtils.create(() -> {

            Map<String, Object> model = new HashMap<>();
            model.put("path", "/toUsername");
            model.put("code", "username");
            model.put("message", "[" + username + "] already exists");

            return Collections.singletonList(model);

        });
        JsonNode message = response.as(JsonNode.class);
        assertThat(message, is(expectedMessage));

    }

    @Test
    public void moveFailsBecauseUsernameNotFound() throws UsernameAlreadyExistsException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And mock service

        Mockito.when(loginResource.get(Mockito.eq(username))).thenReturn(Optional.empty());

        // And token

        String accessToken = JWT.create().withSubject(username).withArrayClaim("scope", new String[] { "login:update" })
                .withClaim("client_id", "clientId1").sign(algorithm);

        // When perform post

        Map<String, Object> login = new HashMap<>();
        login.put("fromUsername", username);
        login.put("toUsername", "jean.dupont@gmail.com");

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .body(login).post(restTemplate.getRootUri() + URL + "/move");

        // Then check status

        assertThat(response.getStatusCode(), is(HttpStatus.BAD_REQUEST.value()));

        // And check message

        JsonNode expectedMessage = JsonNodeUtils.create(() -> {

            Map<String, Object> model = new HashMap<>();
            model.put("path", "/fromUsername");
            model.put("code", "not_found");
            model.put("message", "[" + username + "] not found");

            return Collections.singletonList(model);

        });
        JsonNode message = response.as(JsonNode.class);
        assertThat(message, is(expectedMessage));

    }

    @Test
    public void moveFailsBecauseForbidden() throws UsernameAlreadyExistsException {

        // Given user_name

        String username = "jean.dupond@gmail.com";

        // And token

        String accessToken = JWT.create().withSubject("jean.dupont@gmail.com").withArrayClaim("scope", new String[] { "login:update" })
                .withClaim("client_id", "clientId1").sign(algorithm);

        // When perform post

        Map<String, Object> login = new HashMap<>();
        login.put("fromUsername", username);
        login.put("toUsername", "jean.dupont@gmail.com");

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .body(login).post(restTemplate.getRootUri() + URL + "/move");

        // Then check status

        assertThat(response.getStatusCode(), is(HttpStatus.FORBIDDEN.value()));

    }

}
