package com.exemple.authorization.password;

import java.util.Map;

import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Component;

import com.exemple.authorization.common.security.AuthorizationContextSecurity;
import com.exemple.authorization.core.feature.FeatureConfiguration;
import com.exemple.authorization.password.model.NewPassword;
import com.exemple.authorization.password.token.AccessTokenBuilder;
import com.exemple.authorization.resource.login.LoginResource;
import com.exemple.authorization.resource.login.model.LoginEntity;

import jakarta.annotation.security.RolesAllowed;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import lombok.RequiredArgsConstructor;

@Path("/v1/new_password")
@Component
@RequiredArgsConstructor
public class NewPasswordApi {

    @Context
    private ContainerRequestContext servletContext;

    private final LoginResource loginResource;

    private final KafkaTemplate<String, Map<String, Object>> template;

    private final AccessTokenBuilder accessTokenBuilder;

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @RolesAllowed("ROLE_APP")
    public Response post(@NotNull @Valid NewPassword newPassword, @NotBlank @HeaderParam(FeatureConfiguration.APP_HEADER) String app) {

        AuthorizationContextSecurity securityContext = (AuthorizationContextSecurity) servletContext.getSecurityContext();
        loginResource.get(newPassword.getLogin())
                .map((LoginEntity login) -> accessTokenBuilder.createAccessToken(newPassword, app, securityContext))
                .ifPresent((String token) -> {
                    var data = Map.of("token", token);
                    var message = MessageBuilder.withPayload(data).setHeader(KafkaHeaders.TOPIC, "new_password").build();
                    template.send(message);
                });

        return Response.status(Status.NO_CONTENT).build();

    }

}
