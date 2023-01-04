package com.exemple.authorization.resource.oauth2;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.datastax.oss.driver.api.core.CqlSession;
import com.exemple.authorization.resource.oauth2.dao.OAuth2Dao;
import com.exemple.authorization.resource.oauth2.mapper.OAuth2Mapper;
import com.exemple.authorization.resource.oauth2.model.OAuth2Entity;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class OAuth2Resource {

    private final CqlSession session;

    public void save(OAuth2Entity oauth2) {
        dao().create(oauth2);
    }
    
    public Optional<OAuth2Entity> findById(String id) {
        return dao().findById(id);
    }

    public Optional<OAuth2Entity> findByAuthorizationCodeValue(String token) {
        return dao().findByAuthorizationCodeValue(token);
    }

    public Optional<OAuth2Entity> findByRefreshTokenValue(String token) {
        return dao().findByRefreshTokenValue(token);
    }

    private OAuth2Dao dao() {

        return OAuth2Mapper.builder(session).withDefaultKeyspace("main").build().oAuth2Dao();
    }
}
