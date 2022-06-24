package com.exemple.authorization.core;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.springframework.util.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.JWTPartsParser;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.jwt.interfaces.Payload;
import com.exemple.authorization.common.LoggingFilter;
import com.exemple.authorization.core.client.AuthorizationClientBuilder;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(classes = { AuthorizationTestConfiguration.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
@Slf4j
public class AuthorizationCredentialsTest extends AbstractTestNGSpringContextTests {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private AuthorizationClientBuilder authorizationClientBuilder;

    private String accessToken;

    private RequestSpecification requestSpecification;

    @BeforeClass
    private void init() throws Exception {

        String password = "{bcrypt}" + BCrypt.hashpw("secret", BCrypt.gensalt());

        authorizationClientBuilder

                .withClient("test").secret(password).authorizedGrantTypes("client_credentials").redirectUris("xxx").scopes("account:create")
                .autoApprove("account:create").authorities("ROLE_APP").resourceIds("app1").additionalInformation("keyspace=test")

                .and()

                .withClient("resource").secret(password).authorizedGrantTypes("client_credentials").authorities("ROLE_TRUSTED_CLIENT")
                .additionalInformation("keyspace=test")

                .and().build();

    }

    @BeforeMethod
    private void before() {

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG));

    }

    @Test
    public void credentialsSuccess() {

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "client_credentials");

        Response response = requestSpecification.auth().basic("test", "secret").formParams(params).post(restTemplate.getRootUri() + "/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        accessToken = response.jsonPath().getString("access_token");
        assertThat(accessToken, is(notNullValue()));

    }

    @DataProvider(name = "credentialsFailure")
    private static Object[][] credentialsFailure() {

        return new Object[][] {
                // bad password
                { "test", UUID.randomUUID().toString() },
                // bad login
                { UUID.randomUUID().toString(), "secret" }

        };
    }

    @Test(dataProvider = "credentialsFailure")
    public void credentialsFailure(String login, String password) {

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "client_credentials");

        Response response = requestSpecification.auth().basic(login, password).formParams(params).post(restTemplate.getRootUri() + "/oauth/token");

        assertThat(response.getStatusCode(), is(HttpStatus.FORBIDDEN.value()));

    }

    @Test(dependsOnMethods = "credentialsSuccess")
    public void checkToken() {

        Map<String, String> params = new HashMap<>();
        params.put("token", accessToken);

        Response response = requestSpecification.auth().basic("resource", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/check_token");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));

        JWTPartsParser parser = new JWTParser();
        Payload payload = parser.parsePayload(response.getBody().print());

        assertThat(payload.getClaim("aud").asArray(String.class), arrayContainingInAnyOrder("app1"));
        assertThat(payload.getClaim("authorities").asArray(String.class), arrayContainingInAnyOrder("ROLE_APP"));
        assertThat(payload.getClaim("scope").asArray(String.class), arrayWithSize(1));
        assertThat(payload.getClaim("scope").asArray(String.class), arrayContainingInAnyOrder("account:create"));

    }

    @Test(dependsOnMethods = "credentialsSuccess")
    public void checkTokenFailure() {

        Map<String, String> params = new HashMap<>();
        params.put("token", accessToken);

        Response response = requestSpecification.auth().basic("test", "secret").formParams(params)
                .post(restTemplate.getRootUri() + "/oauth/check_token");

        assertThat(response.getStatusCode(), is(HttpStatus.FORBIDDEN.value()));

    }

    private static Pattern RSA_PUBLIC_KEY = Pattern.compile("-----BEGIN PUBLIC KEY-----(.*)-----END PUBLIC KEY-----", Pattern.DOTALL);

    @Test(dependsOnMethods = "credentialsSuccess")
    public void tokenKey() throws GeneralSecurityException {

        Response response = requestSpecification.auth().basic("resource", "secret").get(restTemplate.getRootUri() + "/oauth/token_key");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));
        assertThat(response.jsonPath().get("alg"), is(notNullValue()));
        assertThat(response.jsonPath().get("value"), is(notNullValue()));

        Matcher publicKeyMatcher = RSA_PUBLIC_KEY.matcher(response.jsonPath().getString("value"));

        Assert.isTrue(publicKeyMatcher.lookingAt(), "Pattern is invalid");

        final byte[] content = Base64.decodeBase64(publicKeyMatcher.group(1).getBytes(StandardCharsets.UTF_8));

        KeyFactory fact = KeyFactory.getInstance("RSA");
        KeySpec keySpec = new X509EncodedKeySpec(content);
        PublicKey publicKey = fact.generatePublic(keySpec);

        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);

        JWTVerifier verifier = JWT.require(algorithm).withAudience("app1").build();
        Payload payload = verifier.verify(accessToken);

        assertThat(payload.getClaim("aud").asArray(String.class), arrayContainingInAnyOrder("app1"));
        assertThat(payload.getClaim("authorities").asArray(String.class), arrayContainingInAnyOrder("ROLE_APP"));
        assertThat(payload.getClaim("scope").asArray(String.class), arrayWithSize(1));
        assertThat(payload.getClaim("scope").asArray(String.class), arrayContainingInAnyOrder("account:create"));

    }

}
