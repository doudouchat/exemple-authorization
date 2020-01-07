package com.exemple.authorization.resource.login;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;

import com.exemple.authorization.resource.core.ResourceExecutionContext;
import com.exemple.authorization.resource.core.ResourceTestConfiguration;
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
    public void get() {

        LoginEntity login = resource.get("jean.dupond@gmail.com").get();
        assertThat(login.getLogin(), is("jean.dupond@gmail.com"));
        assertThat(login.getPassword(), is(nullValue()));
        assertThat(login.getRoles(), is(empty()));
        assertThat(login.isDisabled(), is(false));
        assertThat(login.isAccountLocked(), is(false));
    }

}
