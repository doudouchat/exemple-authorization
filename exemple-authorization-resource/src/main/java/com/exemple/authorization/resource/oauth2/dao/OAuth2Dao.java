package com.exemple.authorization.resource.oauth2.dao;

import java.util.Optional;

import com.datastax.oss.driver.api.mapper.annotations.Dao;
import com.datastax.oss.driver.api.mapper.annotations.Insert;
import com.datastax.oss.driver.api.mapper.annotations.Select;
import com.exemple.authorization.resource.oauth2.model.OAuth2Entity;

@Dao
public interface OAuth2Dao {

    @Select
    Optional<OAuth2Entity> findById(String id);

    @Insert
    boolean create(OAuth2Entity oauth2);
}
