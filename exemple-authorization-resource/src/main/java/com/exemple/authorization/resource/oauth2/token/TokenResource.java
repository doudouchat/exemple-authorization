package com.exemple.authorization.resource.oauth2.token;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.datastax.oss.driver.api.core.CqlSession;
import com.exemple.authorization.resource.oauth2.model.AccessTokenEntity;
import com.exemple.authorization.resource.oauth2.model.RefreshTokenEntity;
import com.exemple.authorization.resource.oauth2.token.dao.AccessTokenDao;
import com.exemple.authorization.resource.oauth2.token.dao.RefreshTokenDao;
import com.exemple.authorization.resource.oauth2.token.mapper.AccessTokenMapper;
import com.exemple.authorization.resource.oauth2.token.mapper.RefreshTokenMapper;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TokenResource {

    private final CqlSession session;

    public void save(AccessTokenEntity token) {
        accessTokenDao().create(token);
    }

    public void save(RefreshTokenEntity token) {
        refreshTokenDao().create(token);
    }

    public Optional<AccessTokenEntity> findByAuthorizationCodeValue(String token) {
        return accessTokenDao().findByAuthorizationCodeValue(token);
    }

    public Optional<RefreshTokenEntity> findByRefreshCodeValue(String token) {
        return refreshTokenDao().findByRefreshCodeValue(token);
    }

    private AccessTokenDao accessTokenDao() {
        return AccessTokenMapper.builder(session).withDefaultKeyspace("main").build().accessTokenDao();
    }

    private RefreshTokenDao refreshTokenDao() {
        return RefreshTokenMapper.builder(session).withDefaultKeyspace("main").build().refreshTokenDao();
    }
}
