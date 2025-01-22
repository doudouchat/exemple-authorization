package com.exemple.authorization.resource.oauth2.token.dao;

import java.util.Optional;

import com.datastax.oss.driver.api.mapper.annotations.Dao;
import com.datastax.oss.driver.api.mapper.annotations.Insert;
import com.datastax.oss.driver.api.mapper.annotations.Select;
import com.exemple.authorization.resource.oauth2.model.RefreshTokenEntity;

@Dao
public interface RefreshTokenDao {

    @Select
    Optional<RefreshTokenEntity> findByRefreshCodeValue(String code);

    @Insert
    boolean create(RefreshTokenEntity refreshToken);
}
