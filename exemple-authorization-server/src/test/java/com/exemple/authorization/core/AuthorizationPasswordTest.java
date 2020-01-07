package com.exemple.authorization.core;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;

import org.mindrot.jbcrypt.BCrypt;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.JWTPartsParser;
import com.auth0.jwt.interfaces.Payload;
import com.exemple.authorization.common.LoggingFilter;
import com.exemple.authorization.core.client.AuthorizationClientBuilder;
import com.exemple.authorization.resource.login.LoginResource;
import com.exemple.authorization.resource.login.model.LoginEntity;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

@SpringBootTest(classes = { AuthorizationTestConfiguration.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
public class AuthorizationPasswordTest extends AbstractTestNGSpringContextTests {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationPasswordTest.class);

    @Autowired
    private TestRestTemplate restTemplate;

    private String accessToken;

    private String refreshToken;

    private String accessTokenBack;

    private String login;

    @Autowired
    private LoginResource resource;

    @Autowired
    private AuthorizationClientBuilder authorizationClientBuilder;

    private RequestSpecification requestSpecification;

    @BeforeClass
    private void init() throws Exception {

        String password = "{bcrypt}" + BCrypt.hashpw("secret", BCrypt.gensalt());

        authorizationClientBuilder

                .withClient("test_user").secret(password).authorizedGrantTypes("password", "authorization_code", "refresh_token").redirectUris("xxx")
                .scopes("account:read", "account:update").autoApprove("account:read", "account:update").authorities("ROLE_APP").resourceIds("app1")
                .additionalInformation("keyspace=test")

                .and()

                .withClient("back_user").secret(password).authorizedGrantTypes("password").scopes("stock:read", "stock:update")
                .autoApprove("stock:read", "stock:update").authorities("ROLE_BACK").resourceIds("app1").additionalInformation("keyspace=test")

                .and()

                .withClient("resource").secret(password).authorizedGrantTypes("client_credentials").authorities("ROLE_TRUSTED_CLIENT")
                .additionalInformation("keyspace=test")

                .and().build();

    }

    @BeforeMethod
    private void before() {

        Mockito.reset(resource);

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG));

    }

    @Test
    public void passwordSuccess() {

        login = "jean.dupond@gmail.com";

        LoginEntity account = new LoginEntity();
        account.setLogin(login);
        account.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));
        account.setRoles(new HashSet<>(Arrays.asList("ROLE_1", "ROLE_2")));

        Mockito.when(resource.get(Mockito.eq(login))).thenReturn(Optional.of(account));

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "password");
        params.put("username", login);
        params.put("password", "123");
        params.put("client_id", "test_user");
        params.put("redirect_uri", "xxx");

        Response response = requestSpecification.auth().basic("test_user", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        accessToken = response.jsonPath().getString("access_token");
        assertThat(accessToken, is(notNullValue()));

        refreshToken = response.jsonPath().getString("refresh_token");
        assertThat(refreshToken, is(notNullValue()));

    }

    @DataProvider(name = "passwordFailure")
    private Object[][] passwordFailure() {

        LoginEntity account1 = new LoginEntity();
        account1.setLogin("jean.dupond@gmail.com");
        account1.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));
        account1.setRoles(new HashSet<>(Arrays.asList("ROLE_1", "ROLE_2")));
        account1.setDisabled(true);

        LoginEntity account2 = new LoginEntity();
        account2.setLogin("jean.dupond@gmail.com");
        account2.setPassword("{bcrypt}" + BCrypt.hashpw("124", BCrypt.gensalt()));
        account2.setRoles(new HashSet<>(Arrays.asList("ROLE_1", "ROLE_2")));

        LoginEntity account3 = new LoginEntity();
        account3.setLogin("jean.dupond@gmail.com");
        account3.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));
        account3.setRoles(new HashSet<>(Arrays.asList("ROLE_1", "ROLE_2")));
        account3.setAccountLocked(true);

        return new Object[][] {

                { Optional.empty(), HttpStatus.UNAUTHORIZED, "Bad Credentials" },

                { Optional.of(account1), HttpStatus.BAD_REQUEST, "User is disabled" },

                { Optional.of(account2), HttpStatus.UNAUTHORIZED, "Bad Credentials" },

                { Optional.of(account3), HttpStatus.BAD_REQUEST, "User account is locked" },

        };
    }

    @Test(dataProvider = "passwordFailure")
    public void passwordFailure(Optional<LoginEntity> loginResponse, HttpStatus expectedStatus, String expectedError) {

        String login = "jean.dupond@gmail.com";

        Mockito.when(resource.get(Mockito.eq(login))).thenReturn(loginResponse);

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "password");
        params.put("username", login);
        params.put("password", "123");
        params.put("client_id", "test_user");
        params.put("redirect_uri", "xxx");

        Response response = requestSpecification.auth().basic("test_user", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/token");

        assertThat(response.getStatusCode(), is(expectedStatus.value()));

        String error = response.jsonPath().getString("error_description");
        assertThat(error, is(expectedError));

    }

    @Test(dependsOnMethods = "passwordSuccess")
    public void checkToken() {

        Map<String, String> params = new HashMap<>();
        params.put("token", accessToken);

        Response response = requestSpecification.auth().basic("resource", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/check_token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        JWTPartsParser parser = new JWTParser();
        Payload payload = parser.parsePayload(response.getBody().print());

        assertThat(payload.getClaim("user_name").asString(), is(this.login));
        assertThat(payload.getSubject(), is(this.login));
        assertThat(payload.getClaim("aud").asArray(String.class), arrayContainingInAnyOrder("app1"));
        assertThat(payload.getClaim("authorities").asArray(String.class), arrayContainingInAnyOrder("ROLE_2", "ROLE_1"));
        assertThat(payload.getClaim("scope").asArray(String.class), arrayContainingInAnyOrder("account:read", "account:update"));

    }

    @Test(dependsOnMethods = "passwordSuccess")
    public void refreshToken() {

        LoginEntity account = new LoginEntity();
        account.setLogin(login);
        account.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));
        account.setRoles(new HashSet<>(Arrays.asList("ROLE_1", "ROLE_2")));

        Mockito.when(resource.get(Mockito.eq(login))).thenReturn(Optional.of(account));

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "refresh_token");
        params.put("client_id", "test_user");
        params.put("refresh_token", refreshToken);

        Response response = requestSpecification.auth().basic("test_user", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        String accessToken = response.jsonPath().getString("access_token");
        assertThat(accessToken, is(notNullValue()));
    }

    @Test
    public void passwordBackSuccess() {

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "password");
        params.put("username", "admin");
        params.put("password", "admin123");
        params.put("client_id", "back_user");
        params.put("redirect_uri", "xxx");

        Response response = requestSpecification.auth().basic("back_user", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        accessTokenBack = response.jsonPath().getString("access_token");
        assertThat(accessTokenBack, is(notNullValue()));

    }

    @Test
    public void passwordBackFailure() {

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "password");
        params.put("username", "bad_login");
        params.put("password", "admin123");
        params.put("client_id", "back_user");
        params.put("redirect_uri", "xxx");

        Response response = requestSpecification.auth().basic("back_user", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.UNAUTHORIZED.value()));

        String error = response.jsonPath().getString("error");
        assertThat(error, is("unauthorized"));

    }

    @Test(dependsOnMethods = "passwordBackSuccess")
    public void checkBackToken() {

        Map<String, String> params = new HashMap<>();
        params.put("token", accessTokenBack);

        Response response = requestSpecification.auth().basic("resource", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/check_token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        JWTPartsParser parser = new JWTParser();
        Payload payload = parser.parsePayload(response.getBody().print());

        assertThat(payload.getClaim("aud").asArray(String.class), arrayContainingInAnyOrder("app1"));
        assertThat(payload.getClaim("authorities").asArray(String.class), arrayContainingInAnyOrder("ROLE_BACK"));
        assertThat(payload.getClaim("scope").asArray(String.class), arrayWithSize(2));
        assertThat(payload.getClaim("scope").asArray(String.class), arrayContainingInAnyOrder("stock:read", "stock:update"));

    }

}
