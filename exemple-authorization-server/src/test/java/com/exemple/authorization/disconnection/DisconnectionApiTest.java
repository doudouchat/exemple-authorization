package com.exemple.authorization.disconnection;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.mindrot.jbcrypt.BCrypt;
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
import com.exemple.authorization.common.LoggingFilter;
import com.exemple.authorization.core.AuthorizationTestConfiguration;
import com.exemple.authorization.core.client.AuthorizationClientBuilder;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

@SpringBootTest(classes = { AuthorizationTestConfiguration.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
public class DisconnectionApiTest extends AbstractTestNGSpringContextTests {

    private static final Logger LOG = LoggerFactory.getLogger(DisconnectionApiTest.class);

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private AuthorizationClientBuilder authorizationClientBuilder;

    @Autowired
    private Algorithm algorithm;

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

                .withClient("resource").secret(password).authorizedGrantTypes("client_credentials").authorities("ROLE_TRUSTED_CLIENT")

                .and().build();

    }

    @BeforeMethod
    private void before() {

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG));

    }

    private String accessToken;

    @Test
    public void disconnection() {

        accessToken = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_ACCOUNT" }).withAudience("app")
                .withJWTId(UUID.randomUUID().toString()).withExpiresAt(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .withClaim("client_id", "clientId1").sign(algorithm);

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .post(restTemplate.getRootUri() + "/ws/v1/disconnection");

        assertThat(response.getStatusCode(), is(HttpStatus.NO_CONTENT.value()));

    }

    @DataProvider(name = "disconnectionFailure")
    private Object[][] disconnectionFailure() {

        String accessToken1 = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_ACCOUNT" }).withAudience("app")
                .withExpiresAt(Date.from(Instant.now().plus(1, ChronoUnit.DAYS))).withClaim("client_id", "clientId1").sign(algorithm);

        String accessToken2 = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_ACCOUNT" }).withAudience("app")
                .withJWTId(UUID.randomUUID().toString()).withClaim("client_id", "clientId1").sign(algorithm);

        return new Object[][] {
                // no jti
                { accessToken1 },
                // no exp
                { accessToken2 }

        };
    }

    @Test(dataProvider = "disconnectionFailure")
    public void disconnectionFailure(String accessToken) {

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .post(restTemplate.getRootUri() + "/ws/v1/disconnection");

        assertThat(response.getStatusCode(), is(HttpStatus.BAD_REQUEST.value()));

    }

    @Test(dependsOnMethods = "disconnection")
    public void checkToken() {

        Map<String, String> params = new HashMap<>();
        params.put("token", accessToken);

        Response response = requestSpecification.auth().basic("resource", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/check_token");

        assertThat(response.getStatusCode(), is(HttpStatus.BAD_REQUEST.value()));
        assertThat(response.jsonPath().getString("error"), is("invalid_token"));

    }

}
