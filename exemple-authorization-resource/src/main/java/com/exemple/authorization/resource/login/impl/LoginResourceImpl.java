package com.exemple.authorization.resource.login.impl;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.stereotype.Service;

import com.datastax.oss.driver.api.core.CqlSession;
import com.exemple.authorization.resource.core.ResourceExecutionContext;
import com.exemple.authorization.resource.login.LoginResource;
import com.exemple.authorization.resource.login.dao.LoginDao;
import com.exemple.authorization.resource.login.mapper.LoginMapper;
import com.exemple.authorization.resource.login.model.LoginEntity;

@Service
public class LoginResourceImpl implements LoginResource {

    private final CqlSession session;

    private final ConcurrentMap<String, LoginMapper> mappers;

    public LoginResourceImpl(CqlSession session) {

        this.session = session;
        this.mappers = new ConcurrentHashMap<>();
    }

    @Override
    public Optional<LoginEntity> get(String username) {

        return Optional.ofNullable(get().findByUsername(username));
    }

    private LoginDao get() {

        return mappers.computeIfAbsent(ResourceExecutionContext.get().keyspace(), this::build).loginDao();
    }

    private LoginMapper build(String keyspace) {

        return LoginMapper.builder(session).withDefaultKeyspace(keyspace).build();
    }

}
