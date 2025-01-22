package com.exemple.authorization.resource.oauth2.token.mapper;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.mapper.MapperBuilder;
import com.datastax.oss.driver.api.mapper.annotations.DaoFactory;
import com.datastax.oss.driver.api.mapper.annotations.Mapper;
import com.exemple.authorization.resource.oauth2.token.dao.AccessTokenDao;

@Mapper
public interface AccessTokenMapper {

    @DaoFactory
    AccessTokenDao accessTokenDao();

    static MapperBuilder<AccessTokenMapper> builder(CqlSession session) {
        return new AccessTokenMapperBuilder(session);
    }
}
