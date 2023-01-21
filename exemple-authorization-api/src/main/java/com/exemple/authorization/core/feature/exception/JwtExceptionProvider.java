package com.exemple.authorization.core.feature.exception;

import org.springframework.security.oauth2.jwt.JwtException;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
public class JwtExceptionProvider implements ExceptionMapper<JwtException> {

    @Override
    public Response toResponse(JwtException e) {

        return Response.status(Status.UNAUTHORIZED).type(MediaType.APPLICATION_JSON_TYPE).entity(e.getMessage()).build();
    }
}
