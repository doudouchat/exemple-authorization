package com.exemple.authorization.resource.login;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;

import com.exemple.authorization.resource.core.ResourceExecutionContext;
import com.exemple.authorization.resource.core.ResourceTestConfiguration;
import com.exemple.authorization.resource.login.exception.UsernameAlreadyExistsException;
import com.exemple.authorization.resource.login.model.LoginEntity;

@ContextConfiguration(classes = ResourceTestConfiguration.class)
public class LoginResourceTest extends AbstractTestNGSpringContextTests {

    @Autowired
    private LoginResource resource;

    @BeforeSuite
    public void initKeyspace() {

        ResourceExecutionContext.get().setKeyspace("test");

    }

    @AfterSuite
    public void destroy() {

        ResourceExecutionContext.destroy();

    }

    @Test
    public void create() throws UsernameAlreadyExistsException {

        // Given login

        String username = UUID.randomUUID() + "gmail.com";

        LoginEntity login = new LoginEntity();
        login.setUsername(username);
        login.setPassword("mdp123");
        login.setDisabled(true);
        login.setAccountLocked(true);
        login.setRoles(new HashSet<>(Arrays.asList("role1", "role2")));

        // When perform

        resource.save(login);

        // Then check login

        LoginEntity actualLogin = resource.get(username).get();
        assertThat(actualLogin.getUsername(), is(username));
        assertThat(actualLogin.getPassword(), is("mdp123"));
        assertThat(actualLogin.getRoles(), containsInAnyOrder("role1", "role2"));
        assertThat(actualLogin.isDisabled(), is(true));
        assertThat(actualLogin.isAccountLocked(), is(true));
    }

    @Test(expectedExceptions = UsernameAlreadyExistsException.class)
    public void createFailureIfUsernameAlreadyExists() throws UsernameAlreadyExistsException {

        // Given login

        LoginEntity login = new LoginEntity();
        login.setUsername("jean.dupond@gmail.com");
        login.setPassword("mdp123");
        login.setDisabled(true);
        login.setAccountLocked(true);
        login.setRoles(new HashSet<>(Arrays.asList("role1", "role2")));

        // When perform

        resource.save(login);

    }

    @Test
    public void get() {

        LoginEntity login = resource.get("jean.dupond@gmail.com").get();
        assertThat(login.getUsername(), is("jean.dupond@gmail.com"));
        assertThat(login.getPassword(), is(nullValue()));
        assertThat(login.getRoles(), is(empty()));
        assertThat(login.isDisabled(), is(false));
        assertThat(login.isAccountLocked(), is(false));
    }

    @Test
    public void update() throws UsernameAlreadyExistsException {

        // Given login

        String username = UUID.randomUUID() + "gmail.com";

        LoginEntity login = new LoginEntity();
        login.setUsername(username);
        login.setPassword("mdp123");
        login.setDisabled(true);
        login.setAccountLocked(true);
        login.setRoles(new HashSet<>(Arrays.asList("role1", "role2")));

        resource.save(login);

        // When perform

        login.setPassword("mdp124");
        login.setDisabled(false);
        login.setAccountLocked(false);
        login.setRoles(new HashSet<>(Arrays.asList("role1", "role3")));

        resource.update(login);

        // Then check login

        LoginEntity actualLogin = resource.get(username).get();
        assertThat(actualLogin.getUsername(), is(username));
        assertThat(actualLogin.getPassword(), is("mdp124"));
        assertThat(actualLogin.getRoles(), containsInAnyOrder("role1", "role3"));
        assertThat(actualLogin.isDisabled(), is(false));
        assertThat(actualLogin.isAccountLocked(), is(false));
    }

    @Test
    public void delete() throws UsernameAlreadyExistsException {

        // Given login

        String username = UUID.randomUUID() + "gmail.com";

        LoginEntity login = new LoginEntity();
        login.setUsername(username);

        resource.save(login);

        // When perform

        resource.delete(username);

        // Then check login

        Optional<LoginEntity> actualLogin = resource.get(username);
        assertThat(actualLogin.isPresent(), is(false));

    }

}
