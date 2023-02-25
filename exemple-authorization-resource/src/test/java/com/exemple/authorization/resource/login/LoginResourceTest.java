package com.exemple.authorization.resource.login;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import com.exemple.authorization.resource.core.ResourceExecutionContext;
import com.exemple.authorization.resource.core.ResourceTestConfiguration;
import com.exemple.authorization.resource.login.exception.UsernameAlreadyExistsException;
import com.exemple.authorization.resource.login.model.LoginEntity;

@SpringBootTest(classes = ResourceTestConfiguration.class)
@ActiveProfiles("test")
class LoginResourceTest {

    @Autowired
    private LoginResource resource;

    @BeforeAll
    static void initKeyspace() {

        ResourceExecutionContext.get().setKeyspace("test");

    }

    @AfterAll
    static void destroy() {

        ResourceExecutionContext.destroy();

    }

    @Test
    void create() throws UsernameAlreadyExistsException {

        // Given login

        String username = UUID.randomUUID() + "gmail.com";

        LoginEntity login = new LoginEntity();
        login.setUsername(username);
        login.setPassword("mdp123");
        login.setDisabled(true);
        login.setAccountLocked(true);

        // When perform

        resource.save(login);

        // Then check login

        LoginEntity actualLogin = resource.get(username).get();
        assertAll(
                () -> assertThat(actualLogin.getUsername()).isEqualTo(username),
                () -> assertThat(actualLogin.getPassword()).isEqualTo("mdp123"),
                () -> assertThat(actualLogin.isDisabled()).isTrue(),
                () -> assertThat(actualLogin.isAccountLocked()).isTrue());
    }

    @Test
    void createFailureIfUsernameAlreadyExists() throws UsernameAlreadyExistsException {

        // Given login

        LoginEntity login = new LoginEntity();
        login.setUsername("jean.dupond@gmail.com");
        login.setPassword("mdp123");
        login.setDisabled(true);
        login.setAccountLocked(true);

        // When perform
        Throwable throwable = catchThrowable(() -> resource.save(login));

        // Then check none exception
        assertThat(throwable).isInstanceOfSatisfying(UsernameAlreadyExistsException.class,
                exception -> assertAll(
                        () -> assertThat(exception.getUsername()).isEqualTo(login.getUsername())));

    }

    @Test
    void get() {

        LoginEntity login = resource.get("jean.dupond@gmail.com").get();
        assertAll(
                () -> assertThat(login.getUsername()).isEqualTo("jean.dupond@gmail.com"),
                () -> assertThat(login.getPassword()).isNull(),
                () -> assertThat(login.isDisabled()).isFalse(),
                () -> assertThat(login.isAccountLocked()).isFalse());
    }

    @Test
    void update() throws UsernameAlreadyExistsException {

        // Given login

        String username = UUID.randomUUID() + "gmail.com";

        LoginEntity login = new LoginEntity();
        login.setUsername(username);
        login.setPassword("mdp123");
        login.setDisabled(true);
        login.setAccountLocked(true);

        resource.save(login);

        // When perform

        login.setPassword("mdp124");
        login.setDisabled(false);
        login.setAccountLocked(false);

        resource.update(login);

        // Then check login

        LoginEntity actualLogin = resource.get(username).get();
        assertAll(
                () -> assertThat(actualLogin.getUsername()).isEqualTo(username),
                () -> assertThat(actualLogin.getPassword()).isEqualTo("mdp124"),
                () -> assertThat(actualLogin.isDisabled()).isFalse(),
                () -> assertThat(actualLogin.isAccountLocked()).isFalse());

    }

    @Test
    void delete() throws UsernameAlreadyExistsException {

        // Given login

        String username = UUID.randomUUID() + "gmail.com";

        LoginEntity login = new LoginEntity();
        login.setUsername(username);

        resource.save(login);

        // When perform

        resource.delete(username);

        // Then check login

        Optional<LoginEntity> actualLogin = resource.get(username);
        assertThat(actualLogin).isEmpty();

    }

}
