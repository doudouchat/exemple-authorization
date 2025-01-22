package com.exemple.authorization.resource.oauth2.token.mapper;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.mapper.MapperBuilder;
import com.datastax.oss.driver.api.mapper.annotations.DaoFactory;
import com.datastax.oss.driver.api.mapper.annotations.Mapper;
import com.exemple.authorization.resource.oauth2.token.dao.RefreshTokenDao;

@Mapper
public interface RefreshTokenMapper {

    @DaoFactory
    RefreshTokenDao refreshTokenDao();

    static MapperBuilder<RefreshTokenMapper> builder(CqlSession session) {
        return new RefreshTokenMapperBuilder(session);
    }
}
