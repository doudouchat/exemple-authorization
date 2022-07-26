package com.exemple.authorization.disconnection;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

import javax.annotation.security.RolesAllowed;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import com.auth0.jwt.RegisteredClaims;
import com.auth0.jwt.interfaces.Payload;
import com.exemple.authorization.common.security.AuthorizationContextSecurity;
import com.exemple.authorization.core.token.AuthorizationTokenConfiguration;
import com.hazelcast.core.HazelcastInstance;

import lombok.RequiredArgsConstructor;

@Path("/v1/disconnection")
@Component
@RequiredArgsConstructor
public class DisconnectionApi {

    @Context
    private ContainerRequestContext servletContext;

    @Qualifier("client")
    private final HazelcastInstance hazelcastInstance;

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed("ROLE_ACCOUNT")
    public void disconnection() {

        Payload payload = ((AuthorizationContextSecurity) servletContext.getSecurityContext()).getPayload();

        if (payload.getId() == null) {
            throw new BadRequestException(RegisteredClaims.JWT_ID + " is required in accessToken");
        }

        if (payload.getExpiresAt() == null) {
            throw new BadRequestException(RegisteredClaims.EXPIRES_AT + " is required in accessToken");
        }

        hazelcastInstance.getMap(AuthorizationTokenConfiguration.TOKEN_BLACK_LIST)
                .put(payload.getId(), payload.getExpiresAt(),
                        ChronoUnit.SECONDS.between(LocalDateTime.now(),
                                Instant.ofEpochMilli(payload.getExpiresAt().getTime()).atZone(ZoneId.systemDefault()).toLocalDateTime()),
                        TimeUnit.SECONDS);
    }

}
