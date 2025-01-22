package com.exemple.authorization.resource.oauth2.token.dao;

import java.util.Optional;

import com.datastax.oss.driver.api.mapper.annotations.Dao;
import com.datastax.oss.driver.api.mapper.annotations.Insert;
import com.datastax.oss.driver.api.mapper.annotations.Select;
import com.exemple.authorization.resource.oauth2.model.AccessTokenEntity;

@Dao
public interface AccessTokenDao {

    @Select
    Optional<AccessTokenEntity> findByAuthorizationCodeValue(String code);

    @Insert
    boolean create(AccessTokenEntity accessToken);
}
