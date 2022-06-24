package com.exemple.authorization.core;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.mindrot.jbcrypt.BCrypt;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
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
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(classes = { AuthorizationTestConfiguration.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
@Slf4j
public class AuthorizationCodeTest extends AbstractTestNGSpringContextTests {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private AuthorizationClientBuilder authorizationClientBuilder;

    @Autowired
    private Algorithm algorithm;

    private String xAuthToken;

    private String location;

    private String accessToken;

    private String username;

    @Autowired
    private LoginResource resource;

    private RequestSpecification requestSpecification;

    private static final Pattern LOCATION;

    static {

        LOCATION = Pattern.compile(".*code=(\\w*)(&state=)?(.*)?", Pattern.DOTALL);
    }

    @BeforeClass
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

                .withClient("resource").secret(password).authorizedGrantTypes("client_credentials").authorities("ROLE_TRUSTED_CLIENT")

                .and().build();

    }

    @BeforeMethod
    private void before() {

        Mockito.reset(resource);

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG));

    }

    @Test
    public void credentials() {

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "client_credentials");

        Response response = requestSpecification.auth().basic("test", "secret").formParams(params).post(restTemplate.getRootUri() + "/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        accessToken = response.jsonPath().getString("access_token");
        assertThat(accessToken, is(notNullValue()));

    }

    @Test(dependsOnMethods = "credentials")
    public void login() {

        username = "jean.dupond@gmail.com";

        LoginEntity account = new LoginEntity();
        account.setUsername(username);
        account.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));

        Mockito.when(resource.get(Mockito.eq(username))).thenReturn(Optional.of(account));

        Response response = requestSpecification.header("Authorization", "Bearer " + accessToken).formParams("username", username, "password", "123")
                .post(restTemplate.getRootUri() + "/login");
        xAuthToken = response.getHeader("X-Auth-Token");

        assertThat(response.getStatusCode(), is(HttpStatus.FOUND.value()));
        assertThat(xAuthToken, is(notNullValue()));
        assertThat(response.getCookies().isEmpty(), is(true));
    }

    @Test(dependsOnMethods = "login")
    public void authorize() {

        String authorizeUrl = restTemplate.getRootUri() + "/oauth/authorize?response_type=code&client_id=test_user&scope=account:read&state=123";
        Response response = requestSpecification.when().redirects().follow(false).header("X-Auth-Token", xAuthToken).get(authorizeUrl);
        location = response.getHeader(HttpHeaders.LOCATION);

        assertThat(response.getStatusCode(), is(HttpStatus.SEE_OTHER.value()));
        assertThat(location, is(notNullValue()));
    }

    @Test(dependsOnMethods = "authorize")
    public void token() {

        Matcher locationMatcher = LOCATION.matcher(location);
        assertThat(locationMatcher.lookingAt(), is(true));

        String code = locationMatcher.group(1);
        String state = locationMatcher.group(3);

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "authorization_code");
        params.put("code", code);
        params.put("client_id", "test_user");
        params.put("redirect_uri", "/ws/test");

        Response response = requestSpecification.auth().basic("test_user", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        accessToken = response.jsonPath().getString("access_token");
        assertThat(accessToken, is(notNullValue()));
        assertThat(state, is("123"));

        JWTPartsParser parser = new JWTParser();
        Payload payload = parser.parsePayload(response.getBody().print());

        assertThat(payload.getSubject(), is(this.username));
        assertThat(payload.getClaim("authorities").asArray(String.class), arrayContainingInAnyOrder("ROLE_ACCOUNT"));

    }

    @Test(dependsOnMethods = "token")
    public void tokenFailure() {

        Matcher locationMatcher = LOCATION.matcher(location);
        assertThat(locationMatcher.lookingAt(), is(true));

        String code = locationMatcher.group(1);

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "authorization_code");
        params.put("code", code);
        params.put("client_id", "test_user");
        params.put("redirect_uri", "xxx");

        Response response = requestSpecification.auth().basic("test_user", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.BAD_REQUEST.value()));

    }

    @Test(dependsOnMethods = "token")
    public void checkToken() {

        Map<String, String> params = new HashMap<>();
        params.put("token", accessToken);

        Response response = requestSpecification.auth().basic("resource", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/check_token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        JWTPartsParser parser = new JWTParser();
        Payload payload = parser.parsePayload(response.getBody().print());

        assertThat(payload.getClaim("user_name").asString(), is(this.username));
        assertThat(payload.getSubject(), is(this.username));
        assertThat(payload.getClaim("aud").asArray(String.class), arrayContainingInAnyOrder("app1"));
        assertThat(payload.getClaim("authorities").asArray(String.class), arrayContainingInAnyOrder("ROLE_ACCOUNT"));
        assertThat(payload.getClaim("scope").asArray(String.class), arrayContainingInAnyOrder("account:read"));

    }

    @DataProvider(name = "loginFailure")
    private Object[][] loginFailure() {

        String accessToken1 = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_ACCOUNT" }).sign(algorithm);
        String accessToken2 = JWT.create().withExpiresAt(new Date(Instant.now().minus(1, ChronoUnit.HOURS).toEpochMilli()))
                .withArrayClaim("authorities", new String[] { "ROLE_APP" }).sign(algorithm);
        String accessToken3 = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_APP" }).sign(algorithm);
        String accessToken4 = JWT.create().sign(algorithm);

        return new Object[][] {
                // not authorities to access
                { "Authorization", "Bearer " + accessToken1 },
                // token is expired
                { "Authorization", "Bearer " + accessToken2 },
                // not bearer
                { "Authorization", accessToken3 },
                // not token
                { "Header", "Bearer " + accessToken3 },
                // auhorities is empty
                { "Authorization", "Bearer " + accessToken4 },
                // token no recognized
                { "Authorization", "Bearer toto" }

        };
    }

    @Test(dataProvider = "loginFailure")
    public void loginFailure(String header, String headerValue) {

        String username = "jean.dupond@gmail.com";

        LoginEntity account = new LoginEntity();
        account.setUsername(username);
        account.setPassword("{bcrypt}" + BCrypt.hashpw("123", BCrypt.gensalt()));

        Mockito.when(resource.get(Mockito.eq(username))).thenReturn(Optional.of(account));

        Response response = requestSpecification.header(header, headerValue).formParams("username", username, "password", "123")
                .post(restTemplate.getRootUri() + "/login");

        assertThat(response.getStatusCode(), is(HttpStatus.FORBIDDEN.value()));

    }

}
