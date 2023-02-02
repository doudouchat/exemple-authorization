package com.exemple.authorization.resource.login;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.stereotype.Service;

import com.datastax.oss.driver.api.core.CqlSession;
import com.exemple.authorization.resource.core.ResourceExecutionContext;
import com.exemple.authorization.resource.login.dao.LoginDao;
import com.exemple.authorization.resource.login.exception.UsernameAlreadyExistsException;
import com.exemple.authorization.resource.login.mapper.LoginMapper;
import com.exemple.authorization.resource.login.model.LoginEntity;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class LoginResource {

    private final CqlSession session;

    private final ConcurrentMap<String, LoginMapper> mappers = new ConcurrentHashMap<>();

    public Optional<LoginEntity> get(String username) {

        return Optional.ofNullable(dao().findByUsername(username));
    }

    public void update(LoginEntity source) {
        dao().update(source);

    }

    public void save(LoginEntity source) {
        boolean notExists = dao().create(source);

        if (!notExists) {

            throw new UsernameAlreadyExistsException(source.getUsername());
        }

    }

    public void delete(String username) {
        dao().deleteByUsername(username);

    }

    private LoginDao dao() {

        return mappers.computeIfAbsent(ResourceExecutionContext.get().keyspace(), this::build).loginDao();
    }

    private LoginMapper build(String keyspace) {

        return LoginMapper.builder(session).withDefaultKeyspace(keyspace).build();
    }

}
