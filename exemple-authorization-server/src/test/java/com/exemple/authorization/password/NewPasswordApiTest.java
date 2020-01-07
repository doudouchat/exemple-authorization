package com.exemple.authorization.password;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.ws.rs.core.SecurityContext;

import org.mindrot.jbcrypt.BCrypt;
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
import com.exemple.authorization.core.AuthorizationTestConfiguration;
import com.exemple.authorization.core.client.AuthorizationClientBuilder;
import com.exemple.authorization.core.feature.FeatureTestConfiguration.TestFilter;
import com.exemple.authorization.resource.login.LoginResource;
import com.exemple.authorization.resource.login.model.LoginEntity;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

@SpringBootTest(classes = { AuthorizationTestConfiguration.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
public class NewPasswordApiTest extends AbstractTestNGSpringContextTests {

    private static final Logger LOG = LoggerFactory.getLogger(NewPasswordApiTest.class);

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

    @BeforeClass
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

    @BeforeMethod
    private void before() {

        Mockito.reset(loginResource);

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG));

    }

    @Test
    public void password() {

        String accessToken = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_APP" }).withAudience("app")
                .withClaim("client_id", "clientId1").sign(algorithm);

        String login = "jean.dupond@gmail.com";

        LoginEntity account = new LoginEntity();
        account.setLogin(login);

        Map<String, Object> newPassword = new HashMap<>();
        newPassword.put("login", login);

        Mockito.when(loginResource.get(Mockito.eq(login))).thenReturn(Optional.of(account));

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .body(newPassword).post(restTemplate.getRootUri() + "/ws/v1/new_password");

        assertThat(response.getStatusCode(), is(HttpStatus.NO_CONTENT.value()));

        assertThat(testFilter.context.getUserPrincipal().getName(), is("clientId1"));
        assertThat(testFilter.context.isUserInRole("ROLE_APP"), is(true));
        assertThat(testFilter.context.isSecure(), is(true));
        assertThat(testFilter.context.getAuthenticationScheme(), is(SecurityContext.BASIC_AUTH));

    }

    private String login;

    private String token;

    @Test
    public void passwordTrustedClient() {

        String accessToken = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_TRUSTED_CLIENT" }).withAudience("app1", "app2")
                .withClaim("client_id", "clientId1").sign(algorithm);

        login = "jean.dupond@gmail.com";

        LoginEntity account = new LoginEntity();
        account.setLogin(login);

        Map<String, Object> newPassword = new HashMap<>();
        newPassword.put("login", login);

        Mockito.when(loginResource.get(Mockito.eq(login))).thenReturn(Optional.of(account));

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app1")
                .body(newPassword).post(restTemplate.getRootUri() + "/ws/v1/new_password");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));
        assertThat(response.jsonPath().getString("token"), is(notNullValue()));

        token = response.jsonPath().getString("token");

        assertThat(testFilter.context.getUserPrincipal().getName(), is("clientId1"));
        assertThat(testFilter.context.isUserInRole("ROLE_TRUSTED_CLIENT"), is(true));
        assertThat(testFilter.context.isSecure(), is(true));
        assertThat(testFilter.context.getAuthenticationScheme(), is(SecurityContext.BASIC_AUTH));

    }

    @Test(dependsOnMethods = "passwordTrustedClient")
    public void checkToken() {

        Map<String, String> params = new HashMap<>();
        params.put("token", token);

        Response response = requestSpecification.auth().basic("resource", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/check_token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        JWTPartsParser parser = new JWTParser();
        Payload payload = parser.parsePayload(response.getBody().print());

        assertThat(payload.getSubject(), is(this.login));
        assertThat(payload.getClaim("aud").asArray(String.class), arrayContainingInAnyOrder("app1", "app2"));
        assertThat(payload.getClaim("authorities").asArray(String.class), arrayContainingInAnyOrder("ROLE_TRUSTED_CLIENT"));
        assertThat(payload.getClaim("scope").asArray(String.class), arrayContainingInAnyOrder("login:read", "login:update"));
        assertThat(payload.getExpiresAt(), is(Date.from(Instant.now(clock).plusSeconds(expiryTime))));
        assertThat(payload.getClaim("singleUse").asBoolean(), is(true));
        assertThat(payload.getId(), is(notNullValue()));

    }

    @DataProvider(name = "passwordFailureForbidden")
    private Object[][] passwordFailureForbidden() {

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
                { "Authorization", "Bearer toto" },
                // bad client id
                { "Authorization", "Bearer " + accessToken5 }

        };
    }

    @Test(dataProvider = "passwordFailureForbidden")
    public void passwordFailureForbidden(String header, String headerValue) {

        String login = "jean.dupond@gmail.com";

        Map<String, Object> newPassword = new HashMap<>();
        newPassword.put("login", login);

        Response response = requestSpecification.contentType(ContentType.JSON).header(header, headerValue).header("app", "app").body(newPassword)
                .post(restTemplate.getRootUri() + "/ws/v1/new_password");

        assertThat(response.getStatusCode(), is(HttpStatus.FORBIDDEN.value()));

    }

    @Test
    public void passwordFailureBadRequest() {

        String accessToken = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_APP" }).withAudience("app")
                .withClaim("client_id", "clientId1").sign(algorithm);

        Map<String, Object> newPassword = new HashMap<>();
        newPassword.put("login", "");

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .body(newPassword).post(restTemplate.getRootUri() + "/ws/v1/new_password");

        assertThat(response.getStatusCode(), is(HttpStatus.BAD_REQUEST.value()));

    }

}
