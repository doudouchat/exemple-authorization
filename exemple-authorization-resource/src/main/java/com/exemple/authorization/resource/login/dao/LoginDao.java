package com.exemple.authorization.resource.login.dao;

import com.datastax.oss.driver.api.mapper.annotations.Dao;
import com.datastax.oss.driver.api.mapper.annotations.Select;
import com.exemple.authorization.resource.login.model.LoginEntity;

@Dao
public interface LoginDao {

    @Select
    LoginEntity findByUsername(String username);

}
