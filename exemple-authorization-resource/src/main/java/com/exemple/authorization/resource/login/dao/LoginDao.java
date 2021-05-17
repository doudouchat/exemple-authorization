package com.exemple.authorization.resource.login.dao;

import com.datastax.oss.driver.api.mapper.annotations.Dao;
import com.datastax.oss.driver.api.mapper.annotations.Delete;
import com.datastax.oss.driver.api.mapper.annotations.Insert;
import com.datastax.oss.driver.api.mapper.annotations.Select;
import com.datastax.oss.driver.api.mapper.annotations.Update;
import com.datastax.oss.driver.api.mapper.entity.saving.NullSavingStrategy;
import com.exemple.authorization.resource.login.model.LoginEntity;

@Dao
public interface LoginDao {

    @Select
    LoginEntity findByUsername(String username);

    @Insert(ifNotExists = true)
    boolean create(LoginEntity login);

    @Update(nullSavingStrategy = NullSavingStrategy.SET_TO_NULL)
    void update(LoginEntity login);

    @Delete(entityClass = LoginEntity.class)
    void deleteByUsername(String username);

}
