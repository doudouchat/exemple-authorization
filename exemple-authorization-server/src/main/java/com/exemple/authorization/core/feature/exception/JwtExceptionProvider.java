package com.exemple.authorization.core.feature.exception;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.springframework.security.oauth2.jwt.JwtException;

@Provider
public class JwtExceptionProvider implements ExceptionMapper<JwtException> {

    @Override
    public Response toResponse(JwtException e) {

        return Response.status(Status.UNAUTHORIZED).type(MediaType.APPLICATION_JSON_TYPE).entity(e.getMessage()).build();
    }
}
