package com.exemple.authorization.core.session;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.MapSession;
import org.springframework.session.Session;
import org.springframework.session.hazelcast.Hazelcast4SessionUpdateEntryProcessor;
import org.springframework.session.hazelcast.config.annotation.web.http.EnableHazelcastHttpSession;
import org.springframework.session.web.http.HeaderHttpSessionIdResolver;
import org.springframework.session.web.http.HttpSessionIdResolver;

import com.hazelcast.client.HazelcastClient;
import com.hazelcast.client.config.ClientConfig;
import com.hazelcast.core.HazelcastInstance;

@EnableHazelcastHttpSession
@Configuration
public class HazelcastHttpSessionConfiguration {

    @Bean
    public HttpSessionIdResolver httpSessionIdResolver() {
        return HeaderHttpSessionIdResolver.xAuthToken();
    }

    @Bean
    public HazelcastInstance client(@Value("${authorization.hazelcast.addresses}") String[] addresses) {
        ClientConfig clientConfig = new ClientConfig();

        clientConfig.getNetworkConfig().addAddress(addresses);
        clientConfig.getUserCodeDeploymentConfig().setEnabled(true).addClass(Session.class).addClass(MapSession.class)
                .addClass(Hazelcast4SessionUpdateEntryProcessor.class);

        return HazelcastClient.newHazelcastClient(clientConfig);
    }

}
