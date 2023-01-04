package com.exemple.authorization.resource.oauth2.mapper;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.mapper.MapperBuilder;
import com.datastax.oss.driver.api.mapper.annotations.DaoFactory;
import com.datastax.oss.driver.api.mapper.annotations.Mapper;
import com.exemple.authorization.resource.oauth2.dao.OAuth2Dao;

@Mapper
public interface OAuth2Mapper {

    @DaoFactory
    OAuth2Dao oAuth2Dao();

    static MapperBuilder<OAuth2Mapper> builder(CqlSession session) {
        return new OAuth2MapperBuilder(session);
    }
}
