package com.exemple.authorization.disconnection;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import com.exemple.authorization.AuthorizationJwtConfiguration;
import com.exemple.authorization.common.security.AuthorizationContextSecurity;
import com.hazelcast.core.HazelcastInstance;

import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import lombok.RequiredArgsConstructor;

@Path("/v1/disconnection")
@Component
@RequiredArgsConstructor
public class DisconnectionApi {

    @Context
    private ContainerRequestContext servletContext;

    private final HazelcastInstance client;

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed("ROLE_ACCOUNT")
    public void disconnection() {

        var jwt = ((AuthorizationContextSecurity) servletContext.getSecurityContext()).getJwt();

        Assert.notNull(jwt.getId(), JwtClaimNames.JTI + " is required in accessToken");

        Assert.notNull(jwt.getExpiresAt(), JwtClaimNames.EXP + " is required in accessToken");

        client.getMap(AuthorizationJwtConfiguration.TOKEN_BLACK_LIST)
                .put(jwt.getId(), jwt.getExpiresAt(), ChronoUnit.SECONDS.between(Instant.now(), jwt.getExpiresAt()), TimeUnit.SECONDS);
    }

}
