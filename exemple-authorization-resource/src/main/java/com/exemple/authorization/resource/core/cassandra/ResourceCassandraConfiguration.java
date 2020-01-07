package com.exemple.authorization.resource.core.cassandra;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.datastax.oss.driver.api.core.CqlSession;

@Configuration
public class ResourceCassandraConfiguration {

    @Value("${authorization.resource.cassandra.addresses}")
    private String[] addresses;

    @Value("${authorization.resource.cassandra.port}")
    private int port;

    @Value("${authorization.resource.cassandra.local_data_center}")
    private String localDataCenter;

    @Bean
    public CqlSession session() {

        return CqlSession.builder().withLocalDatacenter(localDataCenter)
                .addContactPoints(Arrays.stream(addresses).map((String address) -> new InetSocketAddress(address, port)).collect(Collectors.toList()))
                .build();
    }

}
