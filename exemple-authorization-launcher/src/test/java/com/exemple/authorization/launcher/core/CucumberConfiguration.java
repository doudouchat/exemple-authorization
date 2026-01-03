package com.exemple.authorization.launcher.core;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;

import com.datastax.oss.driver.api.core.CqlSession;

import io.cucumber.java.DocStringType;
import io.cucumber.java.ParameterType;
import io.cucumber.java.en.Given;
import io.cucumber.spring.CucumberContextConfiguration;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@SpringBootTest
@CucumberContextConfiguration
@ContextConfiguration(classes = IntegrationTestConfiguration.class)
@ActiveProfiles("test")
public class CucumberConfiguration {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @DocStringType
    public JsonNode json(String content) {
        return MAPPER.readTree(content);
    }

    @ParameterType(".*")
    public UUID id(String id) {
        return UUID.fromString(id);
    }

    @Autowired
    private CqlSession session;

    @Given("delete username {string}")
    public void remove(String username) {

        session.execute("delete from test.login where username = ?", username);

    }

    @Given("create username {string} with password {string}")
    public void create(String username, String password) {

        session.execute("delete from test.login where username = ?", username);
        session.execute("INSERT INTO login (username, password) VALUES (?, ?)", username, "{bcrypt}" + BCrypt.hashpw(password, BCrypt.gensalt()));

    }

    @Given("create disable username {string} with password {string}")
    public void createDisable(String username, String password) {

        session.execute("delete from test.login where username = ?", username);
        session.execute("INSERT INTO login (username, password, disabled) VALUES (?, ?, ?)",
                username, "{bcrypt}" + BCrypt.hashpw(password, BCrypt.gensalt()), true);

    }

}
