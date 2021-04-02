package com.exemple.authorization.core;

import java.io.IOException;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.mockito.Mockito;
import org.osjava.sj.SimpleJndi;
import org.osjava.sj.loader.JndiLoader;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.cassandra.CassandraAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jndi.JndiObjectFactoryBean;

import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.exemple.authorization.core.authentication.AuthenticationConfiguration;
import com.exemple.authorization.core.client.AuthorizationClientTestConfiguration;
import com.exemple.authorization.core.embedded.HazelcastConfiguration;
import com.exemple.authorization.core.feature.FeatureTestConfiguration;
import com.exemple.authorization.core.property.AuthorizationPropertyConfiguration;
import com.exemple.authorization.core.resource.keyspace.AuthorizationResourceKeyspace;
import com.exemple.authorization.core.session.HazelcastHttpSessionConfiguration;
import com.exemple.authorization.core.swagger.SwaggerConfiguration;
import com.exemple.authorization.core.token.AuthorizationTokenConfiguration;
import com.exemple.authorization.resource.login.LoginResource;
import com.github.nosan.boot.autoconfigure.embedded.cassandra.EmbeddedCassandraAutoConfiguration;
import com.google.common.collect.Sets;

@Configuration
@Import({ AuthorizationConfiguration.class, AuthenticationConfiguration.class, AuthorizationTokenConfiguration.class,
        HazelcastHttpSessionConfiguration.class, SwaggerConfiguration.class, AuthorizationClientTestConfiguration.class,
        FeatureTestConfiguration.class, HazelcastConfiguration.class })
@ComponentScan(basePackageClasses = AuthorizationResourceKeyspace.class)
@EnableAutoConfiguration(exclude = { CassandraAutoConfiguration.class, EmbeddedCassandraAutoConfiguration.class })
public class AuthorizationTestConfiguration extends AuthorizationPropertyConfiguration {

    @Bean
    public LoginResource loginResource() {
        return Mockito.mock(LoginResource.class);
    }

    @Bean
    public ApplicationDetailService ApplicationDetailService() {

        ApplicationDetailService service = Mockito.mock(ApplicationDetailService.class);

        ApplicationDetail detail = new ApplicationDetail();
        detail.setKeyspace("test");
        detail.setClientIds(Sets.newHashSet("clientId1"));

        Mockito.when(service.get(Mockito.anyString())).thenReturn(detail);

        return service;
    }

    @Bean
    public InitialContext initialContext() throws NamingException, IOException {

        System.setProperty(Context.INITIAL_CONTEXT_FACTORY, "org.osjava.sj.SimpleContextFactory");
        System.setProperty(SimpleJndi.ENC, "java:comp");
        System.setProperty(JndiLoader.COLON_REPLACE, "--");
        System.setProperty(JndiLoader.DELIMITER, "/");
        System.setProperty(SimpleJndi.SHARED, "true");
        System.setProperty(SimpleJndi.ROOT, new ClassPathResource("java--comp").getURL().getFile());

        return new InitialContext();

    }

    @Bean
    @DependsOn("initialContext")
    @Override
    public JndiObjectFactoryBean jndiObjectFactoryBean() {

        return super.jndiObjectFactoryBean();
    }
}
