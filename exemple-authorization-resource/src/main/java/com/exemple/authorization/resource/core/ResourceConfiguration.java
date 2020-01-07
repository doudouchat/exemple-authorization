package com.exemple.authorization.resource.core;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.exemple.authorization.resource.core.cassandra.ResourceCassandraConfiguration;

@Configuration
@Import(ResourceCassandraConfiguration.class)
@ComponentScan(basePackages = "com.exemple.authorization.resource")
public class ResourceConfiguration {

}
