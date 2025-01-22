package com.exemple.authorization.resource.oauth2;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.datastax.oss.driver.api.core.CqlSession;
import com.exemple.authorization.resource.oauth2.dao.OAuth2Dao;
import com.exemple.authorization.resource.oauth2.mapper.OAuth2Mapper;
import com.exemple.authorization.resource.oauth2.model.AccessTokenEntity;
import com.exemple.authorization.resource.oauth2.model.OAuth2Entity;
import com.exemple.authorization.resource.oauth2.model.RefreshTokenEntity;
import com.exemple.authorization.resource.oauth2.token.TokenResource;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class OAuth2Resource {

    private final CqlSession session;

    private final TokenResource tokenResource;

    public void save(OAuth2Entity oauth2) {
        dao().create(oauth2);
        if (oauth2.getAuthorizationCodeValue() != null) {
            tokenResource.save(new AccessTokenEntity(oauth2.getAuthorizationCodeValue(), oauth2.getId()));
        }
        if (oauth2.getRefreshTokenValue() != null) {
            tokenResource.save(new RefreshTokenEntity(oauth2.getRefreshTokenValue(), oauth2.getId()));
        }
    }

    public Optional<OAuth2Entity> findById(String id) {
        return dao().findById(id);
    }

    public Optional<OAuth2Entity> findByAuthorizationCodeValue(String token) {
        return tokenResource.findByAuthorizationCodeValue(token)
                .map(AccessTokenEntity::getOauth2Id)
                .flatMap(id -> dao().findById(id));
    }

    public Optional<OAuth2Entity> findByRefreshTokenValue(String token) {
        return tokenResource.findByRefreshCodeValue(token)
                .map(RefreshTokenEntity::getOauth2Id)
                .flatMap(id -> dao().findById(id));
    }

    private OAuth2Dao dao() {
        return OAuth2Mapper.builder(session).withDefaultKeyspace("main").build().oAuth2Dao();
    }
}
