package com.exemple.authorization.password;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import javax.ws.rs.core.SecurityContext;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.mindrot.jbcrypt.BCrypt;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.listener.ContainerProperties;
import org.springframework.kafka.listener.KafkaMessageListenerContainer;
import org.springframework.kafka.listener.MessageListener;
import org.springframework.kafka.support.serializer.JsonDeserializer;
import org.springframework.kafka.test.EmbeddedKafkaBroker;
import org.springframework.kafka.test.utils.ContainerTestUtils;
import org.springframework.kafka.test.utils.KafkaTestUtils;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
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
public class NewPasswordApiTest extends AbstractTestNGSpringContextTests {

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
    private EmbeddedKafkaBroker embeddedKafkaBroker;

    @Autowired
    private Clock clock;

    @Value("${authorization.password.expiryTime}")
    private long expiryTime;

    private RequestSpecification requestSpecification;

    private KafkaMessageListenerContainer<String, Map<String, Object>> container;

    private BlockingQueue<ConsumerRecord<String, Map<String, Object>>> records;

    private String username = "jean.dupond@gmail.com";

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

    @BeforeClass
    public void createConsumer() throws Exception {

        records = new LinkedBlockingQueue<>();

        Map<String, Object> consumerProperties = KafkaTestUtils.consumerProps("group_consumer_test", "false", embeddedKafkaBroker);
        DefaultKafkaConsumerFactory<String, Map<String, Object>> consumerFactory = new DefaultKafkaConsumerFactory<>(consumerProperties,
                new StringDeserializer(), new JsonDeserializer<>(Map.class, false));
        ContainerProperties containerProperties = new ContainerProperties("new_password");
        container = new KafkaMessageListenerContainer<>(consumerFactory, containerProperties);

        MessageListener<String, Map<String, Object>> listener = records::add;

        container.setupMessageListener(listener);

        container.start();

        ContainerTestUtils.waitForAssignment(container, embeddedKafkaBroker.getPartitionsPerTopic());
    }

    @AfterClass
    private void closeConsumer() {

        container.stop();

    }

    @BeforeMethod
    private void before() {

        Mockito.reset(loginResource);

        requestSpecification = RestAssured.given().filters(new LoggingFilter(LOG));

    }

    @Test
    public void password() throws InterruptedException {

        String accessToken = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_APP" }).withAudience("app")
                .withClaim("client_id", "clientId1").sign(algorithm);

        LoginEntity account = new LoginEntity();
        account.setUsername(username);

        Map<String, Object> newPassword = new HashMap<>();
        newPassword.put("login", username);

        Mockito.when(loginResource.get(Mockito.eq(username))).thenReturn(Optional.of(account));

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .body(newPassword).post(restTemplate.getRootUri() + "/ws/v1/new_password");

        assertThat(response.getStatusCode(), is(HttpStatus.NO_CONTENT.value()));

        assertThat(testFilter.context.getUserPrincipal().getName(), is("clientId1"));
        assertThat(testFilter.context.isUserInRole("ROLE_APP"), is(true));
        assertThat(testFilter.context.isSecure(), is(true));
        assertThat(testFilter.context.getAuthenticationScheme(), is(SecurityContext.BASIC_AUTH));

        // And check message
        ConsumerRecord<String, Map<String, Object>> received = records.poll(60, TimeUnit.SECONDS);
        assertThat(received, is(notNullValue()));
        assertThat(received.value().get("token"), is(notNullValue()));

        // And check token
        Payload payload = JWT.decode((String) received.value().get("token"));

        assertThat(payload.getSubject(), is(username));
        assertThat(payload.getClaim("authorities").asArray(String.class), arrayContainingInAnyOrder("ROLE_APP"));
        assertThat(payload.getClaim("scope").asArray(String.class), arrayContainingInAnyOrder("login:read", "login:update"));
        assertThat(payload.getExpiresAt(), is(Date.from(Instant.now(clock).plusSeconds(expiryTime))));
        assertThat(payload.getId(), is(notNullValue()));
    }

    @Test
    public void passwordButLoginNotExist() throws InterruptedException {

        String accessToken = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_APP" }).withAudience("app")
                .withClaim("client_id", "clientId1").sign(algorithm);

        Map<String, Object> newPassword = new HashMap<>();
        newPassword.put("login", username);

        Mockito.when(loginResource.get(Mockito.eq(username))).thenReturn(Optional.empty());

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app")
                .body(newPassword).post(restTemplate.getRootUri() + "/ws/v1/new_password");

        assertThat(response.getStatusCode(), is(HttpStatus.NO_CONTENT.value()));

        assertThat(testFilter.context.getUserPrincipal().getName(), is("clientId1"));
        assertThat(testFilter.context.isUserInRole("ROLE_APP"), is(true));
        assertThat(testFilter.context.isSecure(), is(true));
        assertThat(testFilter.context.getAuthenticationScheme(), is(SecurityContext.BASIC_AUTH));

        // And check message
        ConsumerRecord<String, Map<String, Object>> received = records.poll(2, TimeUnit.SECONDS);
        assertThat(received, is(nullValue()));
    }

    @Test
    public void passwordTrustedClient() throws InterruptedException {

        String accessToken = JWT.create().withArrayClaim("authorities", new String[] { "ROLE_TRUSTED_CLIENT" }).withAudience("app1", "app2")
                .withClaim("client_id", "clientId1").sign(algorithm);

        LoginEntity account = new LoginEntity();
        account.setUsername(username);

        Map<String, Object> newPassword = new HashMap<>();
        newPassword.put("login", username);

        Mockito.when(loginResource.get(Mockito.eq(username))).thenReturn(Optional.of(account));

        Response response = requestSpecification.contentType(ContentType.JSON).header("Authorization", "Bearer " + accessToken).header("app", "app1")
                .body(newPassword).post(restTemplate.getRootUri() + "/ws/v1/new_password");

        assertThat(response.getStatusCode(), is(HttpStatus.OK.value()));
        assertThat(response.jsonPath().getString("token"), is(notNullValue()));

        assertThat(testFilter.context.getUserPrincipal().getName(), is("clientId1"));
        assertThat(testFilter.context.isUserInRole("ROLE_TRUSTED_CLIENT"), is(true));
        assertThat(testFilter.context.isSecure(), is(true));
        assertThat(testFilter.context.getAuthenticationScheme(), is(SecurityContext.BASIC_AUTH));

        // And check message
        ConsumerRecord<String, Map<String, Object>> received = records.poll(2, TimeUnit.SECONDS);
        assertThat(received, is(nullValue()));

        // And check token
        Payload payload = JWT.decode(response.jsonPath().getString("token"));

        assertThat(payload.getSubject(), is(this.username));
        assertThat(payload.getClaim("authorities").asArray(String.class), arrayContainingInAnyOrder("ROLE_TRUSTED_CLIENT"));
        assertThat(payload.getClaim("scope").asArray(String.class), arrayContainingInAnyOrder("login:read", "login:update"));
        assertThat(payload.getExpiresAt(), is(Date.from(Instant.now(clock).plusSeconds(expiryTime))));
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
                { "Authorization", "Bearer " + accessToken1, HttpStatus.FORBIDDEN },
                // token is expired
                { "Authorization", "Bearer " + accessToken2, HttpStatus.UNAUTHORIZED },
                // not bearer
                { "Authorization", accessToken3, HttpStatus.FORBIDDEN },
                // not token
                { "Header", "Bearer " + accessToken3, HttpStatus.FORBIDDEN },
                // auhorities is empty
                { "Authorization", "Bearer " + accessToken4, HttpStatus.FORBIDDEN },
                // token no recognized
                { "Authorization", "Bearer toto", HttpStatus.UNAUTHORIZED },
                // bad client id
                { "Authorization", "Bearer " + accessToken5, HttpStatus.UNAUTHORIZED }

        };
    }

    @Test(dataProvider = "passwordFailureForbidden")
    public void passwordFailureForbidden(String header, String headerValue, HttpStatus expectedStatus) {

        String login = "jean.dupond@gmail.com";

        Map<String, Object> newPassword = new HashMap<>();
        newPassword.put("login", login);

        Response response = requestSpecification.contentType(ContentType.JSON).header(header, headerValue).header("app", "app").body(newPassword)
                .post(restTemplate.getRootUri() + "/ws/v1/new_password");

        assertThat(response.getStatusCode(), is(expectedStatus.value()));

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
