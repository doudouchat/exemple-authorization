package com.exemple.authorization.core.property;

import java.io.FileNotFoundException;
import java.util.Properties;

import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.UrlResource;
import org.springframework.jndi.JndiObjectFactoryBean;
import org.springframework.util.Assert;
import org.springframework.util.ResourceUtils;

@Configuration
public class AuthorizationPropertyConfiguration {

    public static final String JNDI_NAME = "java:comp/env/exemple-authorization-configuration";

    @Bean
    public JndiObjectFactoryBean jndiObjectFactoryBean() {

        JndiObjectFactoryBean jndiObjectFactoryBean = new JndiObjectFactoryBean();
        jndiObjectFactoryBean.setJndiName(JNDI_NAME);
        jndiObjectFactoryBean.setExpectedType(String.class);

        return jndiObjectFactoryBean;
    }

    @Bean
    public PropertySourcesPlaceholderConfigurer propertyPlaceholderConfigurer() throws FileNotFoundException {

        JndiObjectFactoryBean jndiObjectFactoryBean = this.jndiObjectFactoryBean();

        YamlPropertiesFactoryBean propertiesFactoryBean = new YamlPropertiesFactoryBean();
        String resource = (String) jndiObjectFactoryBean.getObject();
        Assert.notNull(resource, jndiObjectFactoryBean.getJndiName() + " is required");
        propertiesFactoryBean.setResources(new UrlResource(ResourceUtils.getURL(resource)));

        Properties properties = propertiesFactoryBean.getObject();
        Assert.notNull(properties, jndiObjectFactoryBean.getJndiName() + " is required");

        PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer = new PropertySourcesPlaceholderConfigurer();
        propertySourcesPlaceholderConfigurer.setProperties(properties);

        return propertySourcesPlaceholderConfigurer;
    }

}
